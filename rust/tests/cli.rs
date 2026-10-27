//! Black-box CLI harness for the `torshammer-rust` binary.
//!
//! The crate is binary-only (no `lib.rs`), so unit tests inside `src/` cannot
//! link `run()`/`main()` (they read `std::env::args`). These integration tests
//! spawn the compiled binary as a subprocess; `cargo-llvm-cov` instruments the
//! child and merges its profile, so the top-level dispatch arms in `run()` and
//! the `main()` entry point are recorded.

use std::process::Command;

/// Path to the built binary, resolved by Cargo for integration tests.
const BIN: &str = env!("CARGO_BIN_EXE_torshammer-rust");

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("failed to spawn torshammer-rust")
}

#[test]
fn cli_version_prints_version_and_exits_zero() {
    let out = run(&["--version"]);
    assert!(out.status.success(), "--version should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TorsHammer"),
        "expected version line, got: {stdout}"
    );
}

#[test]
fn cli_help_lists_usage_and_exit_zero() {
    let out = run(&["--help"]);
    assert!(out.status.success(), "--help should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty(), "help output should not be empty");
}

#[test]
fn cli_no_arguments_prints_help_and_exits_zero() {
    let out = run(&[] as &[&str]);
    assert!(out.status.success(), "no-args should print help and exit 0");
}

#[test]
fn cli_unknown_option_exits_two() {
    let out = run(&["--bogus-flag"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown option must be a usage error"
    );
}

#[test]
fn cli_missing_target_exits_two() {
    // A flag-only invocation with no target is a usage error (exit 2).
    let out = run(&["--json"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a target is required when running"
    );
}

#[test]
fn cli_public_target_refused_without_opt_in_exits_two() {
    // Default-deny guard must reject a public target before any worker runs.
    let out = run(&["--target", "http://8.8.8.8", "--duration", "0.05"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "public target must be refused without --allow-public-targets"
    );
}

#[test]
fn cli_runs_local_target_dispatch_path_and_exits() {
    // Exercise the Action::Run -> run_scan dispatch path end-to-end against a
    // loopback target with a tiny duration so the process terminates promptly.
    // Port 9 (discard) may refuse connections, which the engine tolerates.
    let out = run(&[
        "--target",
        "http://127.0.0.1:9",
        "--mode",
        "idle-hold",
        "--duration",
        "0.05",
        "--concurrency",
        "1",
        "--quiet",
        "--json",
    ]);
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "run path should exit 0 or 1, got {code}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_sigint_triggers_graceful_shutdown() {
    // `--duration 0` means "run until interrupted", so the engine installs its
    // SIGINT handler, enters the monitor loop with a `None` deadline, and only
    // exits when a signal flips the shutdown flag. Signalling a real child is
    // the one way to execute the `unsafe extern "C" fn handle` body (signals.rs)
    // and the shutdown branches in engine::run; cargo-llvm-cov merges the
    // child's profile into the report. The child is a separate process, so the
    // global SHUTDOWN flag never contaminates the in-process unit tests.
    use std::net::TcpListener;
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("addr").port();
    let target = format!("http://127.0.0.1:{port}");

    let mut child = Command::new(BIN)
        .args([
            "--target",
            target.as_str(),
            "--mode",
            "idle-hold",
            "--duration",
            "0",
            "--concurrency",
            "2",
            "--quiet",
            "--json",
        ])
        .spawn()
        .expect("spawn torshammer-rust for SIGINT test");

    // Give the child time to install handlers and enter the loop.
    std::thread::sleep(Duration::from_millis(500));

    let pid = child.id().to_string();
    let signalled = Command::new("kill")
        .args(["-INT", pid.as_str()])
        .status()
        .is_ok();
    if !signalled {
        // `kill` unavailable: abort so the run-until-interrupted child cannot
        // hang the harness.
        let _ = child.kill();
    }
    let status = child.wait().expect("wait for signalled child");
    drop(listener);

    assert!(
        signalled,
        "test requires the `kill` utility to deliver SIGINT"
    );
    assert!(
        status.success(),
        "SIGINT should produce a graceful exit 0, got {status:?}"
    );
}
