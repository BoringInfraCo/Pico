# Pico

Pico is a local-first security tool for AI-assisted development. It records the security-relevant state of your agent environments—agents, tools, permissions, and connections—into a local SQLite database, so you can understand what your agents can actually do.

## Quick Start

```bash
pico init
```

Initializes a Pico workspace, creating `.pico/` with the SQLite database and applying schema migrations. Safe to run repeatedly; it never resets existing state.

```bash
pico scan
```

Runs a scan of the current workspace and records results in the database. Requires `pico init` first.

## Philosophy

Local-first and offline by design. All data stays on your machine. No external APIs or internet required for core functionality.

## Development

```bash
cargo build
cargo test
cargo fmt --check
cargo clippy
```

This model is inspired by [UsefulSoftwareCo/executor](https://github.com/UsefulSoftwareCo/executor) and [rivet-dev/actors](https://github.com/rivet-dev/actors).