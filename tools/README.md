# Development tools

`go run ./tools/standalone_ui.go` serves a loopback-only UI preview on port 3000.
It does not start the bouncer, contact LAPI or block requests. The UI state is
explicitly `preview`; this is not protection acceptance evidence.

`check_introspection.py` compares the executable metadata against `.introspect`.
`ui.test.cjs` exercises actual UI JavaScript with an injected DOM/fetch test double.
`e2e.py` runs the isolated dual-stack Docker acceptance sequence after `make test-env-ready`.
See [testing instructions](../docs/testing.md) for commands and unexecuted checks.
