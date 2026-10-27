# Torshammer 2.0 — one-command developer workflows
# ================================================
# `make` with no target prints this help. Run `make check` for the full
# dual-backend gate set (the same checks CI enforces).
#
# Rust toolchain note: run every Rust target with a single, consistent
# toolchain (e.g. `rustup default stable`). Mixing a distro `cargo` with a
# rustup `clippy-driver` produces corrupt-metadata (E0786) build errors.

PY      ?= python3
VENV    ?= .venv
CARGO   ?= cargo
BIN     := $(VENV)/bin

.DEFAULT_GOAL := help
.PHONY: help venv install dev test lint type cov rust fmt-rust clippy rust-test rust-cov check clean clean-rust publish-dry

help: ## Show this help
	@echo "Torshammer 2.0 — available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create a local virtualenv at $(VENV)
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

install: ## Install the Python CLI (editable) into $(VENV)
	$(BIN)/pip install -e .

dev: ## Install with development extras (pytest, mypy, ruff)
	$(BIN)/pip install -e ".[dev]"

test: ## Run the Python test suite with coverage gate
	$(BIN)/python -m pytest

lint: ## Ruff lint + format check (Python)
	$(BIN)/ruff check src/ tests/
	$(BIN)/ruff format --check src/ tests/

type: ## Mypy static type check (Python)
	$(BIN)/mypy src/torshammer

fmt-rust: ## cargo fmt --check (Rust)
	cd rust && $(CARGO) fmt --check

clippy: ## cargo clippy, warnings treated as errors (Rust)
	cd rust && $(CARGO) clippy --all-targets -- -D warnings

rust: ## Build the Rust backend (release) -> rust/target/release/torshammer-rust
	cd rust && $(CARGO) build --release

rust-test: ## Run the Rust test suite
	cd rust && $(CARGO) test

cov: ## Python line-coverage gate (fails below 100% on src/torshammer)
	$(BIN)/python -m pytest --cov=src/torshammer --cov-report=term-missing --cov-fail-under=100

rust-cov: ## Rust line-coverage gate (cargo-llvm-cov, 100% of rust/src via lcov)
	cd rust && mkdir -p target/llvm-cov && PATH="$(HOME)/.cargo/bin:$(PATH)" cargo llvm-cov --all-targets --lcov --output-path target/llvm-cov/lcov.info
	@$(PY) scripts/rust_cov_gate.py rust/target/llvm-cov/lcov.info

check: lint type cov fmt-rust clippy rust-test rust-cov ## Run every Python + Rust gate

clean: ## Remove build/test artifacts
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache $(VENV)
	$(MAKE) clean-rust

clean-rust: ## Remove the Rust target directory
	cd rust && $(CARGO) clean

publish-dry: ## Validate the distribution without uploading (needs 'dev' extra: twine)
	$(BIN)/python -m build 2>/dev/null || $(BIN)/pip install build
	$(BIN)/python -m twine check dist/*
