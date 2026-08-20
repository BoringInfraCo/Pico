# Pico

Pico discovers the dangerous paths your AI agents create.

Pico is a local-first, offline security tool for AI-assisted development.
It records the security-relevant state of your agent environments - agents,
tools, permissions, and the connections between them - into a local SQLite
database, so you can understand what your agents can actually do. This
release establishes the local foundation: workspace initialization, schema
migrations, and a scan lifecycle that records an empty, verifiable
baseline. Discovery of real agents and providers arrives in later sprints.

## Usage

```
pico init
```

Initializes a Pico workspace. Creates `.pico/` containing the `pico.db`
SQLite database and applies the schema migrations. Safe to run repeatedly:
it never resets or deletes existing state.

```
pico scan
```

Runs a scan of the current workspace and records it in the database. A scan
requires `pico init` to have been run first. In this release a scan performs
no discovery: it starts as RUNNING, completes as COMPLETE, and reports zero
resources, relationships, evidence, and findings.

## Development

```
cargo build
cargo test
cargo fmt --check
cargo clippy
```