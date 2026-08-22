//! UDP attack profile: send real datagrams to a target host:port.
//!
//! The TCP profiles consume one HTTP request per cycle; the ``udp`` mode
//! instead produces genuine UDP traffic. Each cycle opens a real datagram
//! socket and slowly drips randomized 1..32 byte payloads toward the target
//! (defaulting to ``base_post_length`` bytes total) so ``send_to`` ends up
//! exercised over the network, mirroring the Python backend's datagram loop.

use super::rng::Rng;
use super::signals;
use super::stats::Stats;
use super::EngineConfig;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Bind a fresh local datagram socket (the source port is kernel-assigned).
pub fn open(_config: &EngineConfig) -> std::io::Result<UdpSocket> {
    UdpSocket::bind("0.0.0.0:0")
}

/// Build the remote ``host:port`` address string (brackets IPv6 literals).
fn target_address(config: &EngineConfig) -> String {
    if config.host.contains(':') {
        format!("[{}]:{}", config.host, config.port)
    } else {
        format!("{}:{}", config.host, config.port)
    }
}

fn should_stop(running: &AtomicBool) -> bool {
    !running.load(Ordering::Relaxed) || signals::shutdown_requested()
}

/// Slow-drip datagrams to the target until ``base_post_length`` payload bytes
/// have been sent (one cycle) or the run is interrupted.
///
/// Returns ``true`` if the cycle completed naturally.
pub fn run(
    config: &EngineConfig,
    sock: &mut UdpSocket,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let length = rng.range_usize(
        (config.base_post_length / 2).max(1),
        config.base_post_length.max(1),
    );

    let mut sent = 0usize;
    while !should_stop(running) && sent < length {
        let remaining = (length - sent).max(1);
        let size = rng.range_usize(1, remaining.min(32));
        let mut payload = Vec::<u8>::new();
        for _ in 0..size {
            payload.push(ALNUM[rng.range_usize(0, ALNUM.len() - 1)]);
        }
        // send_to consumes its address argument, so build it fresh each datagram.
        let peer = target_address(config);
        match sock.send_to(payload.as_ref(), peer) {
            Ok(_) => {
                stats.add_sent(size as u64);
                sent += size;
            }
            Err(_) => break,
        }
        super::sleep_slices(running, rng.range_f64(config.delay_min, config.delay_max));
    }
    !should_stop(running)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(port: u16) -> EngineConfig {
        EngineConfig {
            host: "127.0.0.1".into(),
            port,
            path: "/".into(),
            header_host: "127.0.0.1".into(),
            secure: false,
            mode: "udp".into(),
            concurrency: 1,
            duration: 1.0,
            delay_min: 0.0005,
            delay_max: 0.001,
            connect_timeout: 3.0,
            base_post_length: 128,
            randomize_path: true,
            method: None,
            custom_headers: vec![],
            custom_body: None,
            json: true,
            stats_interval: 0.2,
            quiet: true,
            verbose: false,
            max_errors: 0,
            fail_under: 0,
            fail_on_zero: false,
        }
    }

    #[test]
    fn udp_profile_sends_real_datagrams_to_a_local_receiver() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = receiver.local_addr().unwrap().port();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();

        let collector = std::thread::spawn(move || {
            let _ = receiver.set_read_timeout(Some(std::time::Duration::from_millis(30)));
            let mut datagrams = 0u32;
            let mut bytes = 0u64;
            let mut buf = [0u8; 2048];
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match receiver.recv_from(&mut buf[..]) {
                    Ok((n, _)) => {
                        datagrams += 1;
                        bytes += n as u64;
                    }
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                }
            }
            (datagrams, bytes)
        });

        let config = cfg(port);
        let mut rng = Rng::new(3);
        let stats = Stats::new();
        let running = AtomicBool::new(true);
        let mut sock = open(&config).unwrap();
        let completed = run(&config, &mut sock, &stats, &running, &mut rng);

        assert!(completed, "udp profile should complete with running=true");
        assert!(
            stats.bytes_sent() >= 64,
            "expected datagram bytes to be counted"
        );

        stop.store(true, Ordering::Relaxed);
        let (datagrams, bytes) = collector.join().unwrap();
        assert!(
            datagrams > 0,
            "expected the receiver to get datagrams, got {datagrams}"
        );
        assert!(bytes > 0, "expected received bytes, got {bytes}");
        assert_eq!(
            stats.bytes_sent(),
            bytes,
            "all sent datagram bytes should arrive intact"
        );
    }
}
