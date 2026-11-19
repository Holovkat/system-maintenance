---
name: storage
description: "Automatically collect storage evidence, send directly to System 1 and report approval/retention/fallout tables. Use for system-maintenance:storage, system-maintenance:recover, resumable cleanup sessions or disk-space discovery."
---

# Storage

For space discovery (deep or section-scoped), read
[automatic recovery](references/automatic.md) and invoke the read-only runner
once. It collects native evidence, sends it directly to System 1 and produces
the final tables. The agent's role is to analyse that final report and hand it
to the owner; do not assemble an observations file, pre-classify candidates or
manually walk sections. An exception is a report outcome, not permission to
replace the collector or model with agent judgement. No cleanup or process
restart occurs in the discovery invocation.

For subsequent owner-approved execution or explicit low-level session work,
read [cleanup sessions](references/sessions.md). The persistent record owns
evidence, approvals and progress; do not reconstruct these from chat. Work solo
unless the owner authorizes agents. Discovery and an inspection request never
authorize cleanup or service interruption.

The explicit legacy raw-audit/cleanup interfaces retain the flow below. They
are not the default discovery route or a fallback around the automatic report.
A session-bound plan must use `session run`; the standalone cleaner cannot
bypass its gate.

Use the [deterministic storage tool](../../scripts/storage.py). All paths below
are relative to this skill, not the current working directory:

```bash
python3 "<this-skill-directory>/../../scripts/storage.py" audit --save
```

Default audit covers disk capacity, targeted system directories, Docker and
Ollama. Add `--scope external` for bounded external-drive breakdowns, or
`--path "/exact/folder"` to inspect a particular removal candidate. Scopes may
be combined, for example `--scope system,docker,ollama,external`. `--format json`
provides the same report as structured data. The tool writes only its small
report/plan/receipt files unless an approved cleanup command is executed.

## Report and approval

Keep the generated tables: volume/free space; consumers with location and size;
cleanup candidates with stable ID, estimate, native action and status. Distinguish
measured size from estimated reclaimable space. Parent/child measurements and
shared model/image sizes are not additive. An inaccessible or timed-out location
is unmeasured, never zero. Summarize the largest findings in a few sentences.

An audit or a question about candidates authorizes inspection. It does not
authorize deletion. When the owner selects candidate IDs or clearly identifies
rows, prepare a plan using those IDs and the saved report:

```bash
python3 "<this-skill-directory>/../../scripts/storage.py" plan --report REPORT_ID --select ID [ID ...]
```

Use the report ID produced in this chat; a global "last" report may belong to
another chat. Show the selected-item/action table if the exact scope has not already been
reviewed. Once the owner approves that scope, including a follow-up such as
"go ahead", run the plan with its displayed ID. Existing approval persists;
do not ask again for the same items:

```bash
python3 "<this-skill-directory>/../../scripts/storage.py" clean --plan PLAN_ID --approve PLAN_ID
```

The approval argument records an approval already given by the owner; the agent
must not supply it on the strength of an audit request alone. Plan expiry, changed
resources or a blocked check require a fresh report and review of the changed
scope. Do not silently add new candidates or broaden a failed operation.

## Execution

The tool dispatches supported cleanup to native commands: `ollama rm MODEL`,
Docker builder prune and Docker unused-image prune. Each is a separate selectable
action. It preserves unselected Ollama names/digests and binds Docker work to the
same local context. Loaded models require a separately authorized stop before
removal. Docker volumes and databases are never swept by this tool.

An explicitly inspected ordinary filesystem path is an exception when no owning
cleanup command exists. The tool checks its complete metadata fingerprint and
open files, moves it to a same-volume quarantine, validates it, then purges it.
Managed Ollama stores, Docker storage and active simulator storage are protected
from this path action. Prefer the application's own command whenever one exists.
Raw Ollama orphan/blob deletion is unsupported: do not invent another collector.

After execution, present the receipt's results and before/after free-space table.
Report failures and any remaining quarantine path. A metadata/catalog check does
not prove model inference. Never claim a timed-out cleanup completed; reconcile
the actual state before another attempt. No cleanup is performed while creating
or testing this skill unless separately approved.
