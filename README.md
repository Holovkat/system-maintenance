# System Maintenance

A macOS-oriented storage discovery and approval-gated cleanup toolbox for coding
assistants. This standalone repository contains the system-maintenance plugin
v0.3.1 with fresh history; it does not include the source distribution's other
plugins, private history, reports or local runtime state.

## Quick start

Requires Python 3 (standard library only). Native inspection uses macOS tools;
Docker and Ollama inspection additionally require their local services/tools.

```sh
git clone https://github.com/Holovkat/system-maintenance.git
cd system-maintenance
python3 scripts/system_maintenance.py help
python3 scripts/system_maintenance.py recover \
  --goal "Discover reclaimable space; preserve databases, logs, models and active applications"
```

The recovery command collects bounded, read-only metadata, sends evidence to a
System 1 decision gateway, and saves a persistent report. It never performs
cleanup, grants approval or restarts processes. Cleanup requires a separate
exact-plan approval and native safety checks.

## Decision gateway dependency

Automatic classification requires a separately operated JEV-compatible System 1
gateway exposing `POST /v1/decision`. The default is `http://127.0.0.1:8096`;
set `JEV_BASE_URL` to change its origin. The gateway implementation and model are
not included, so cloning this repository alone does not provide classification.
The request and response contract is implemented in
[storage_session.py](scripts/storage_session.py).

An unavailable gateway produces a partial report and explicit review items,
not a silent model fallback. Exit code 2 means review work remains. Numerical
confidence scores are advisory, and every categorical rubric includes an
explicit `fallout` option.

## Assistant integration and documentation

The plugin manifest is [.codex-plugin/plugin.json](.codex-plugin/plugin.json).
The skills use relative paths and can be loaded from this checkout by a
compatible assistant/plugin host. Cloning alone does not register the plugin.

- [Command index](commands.json)
- [Storage skill](skills/storage/SKILL.md)
- [Automatic discovery workflow](skills/storage/references/automatic.md)
- [Sessions, approval and execution](skills/storage/references/sessions.md)

## Safety and privacy

Discovery writes local evidence, reports and session records. Treat those files
as private: they can contain filesystem paths and resource metadata. Review the
gateway configuration before sending evidence to a remote service. Do not
commit generated reports, approvals, credentials or runtime state.

This public export was checked for common credential patterns and personal
absolute paths. CLI help was smoke-tested; no cleanup was run as part of
publication. This is not a comprehensive security audit or a fresh end-to-end
gateway verification.
