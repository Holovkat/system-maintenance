# Automatic discovery and owner handoff

The owner invokes `system-maintenance:storage` for deep space recovery, or
`system-maintenance:recover` directly. Run the registered entry once:

```bash
python3 <plugin>/scripts/system_maintenance.py recover \
  --goal "Discover reclaimable space; preserve databases, logs, models and active applications"
```

The invocation writes only its small session, evidence and report artifacts.
It does not clean anything, grant approval, restart processes, create helper
containers or start databases. Its built-in collectors use native filesystem,
Docker Unix-socket API/CLI and local Ollama observations. No agent-written
observations file is required or accepted by this entry point.

## Roles and outputs

1. **Collector:** inventory native evidence for caches, Docker images/build cache,
   stopped-container groups, unreferenced volumes, registered models and external
   drive contents. Ownership/recovery contracts are a versioned registry;
   unrecognised resources remain unknown. Contents are metadata-only. API env,
   credentials, volume driver options and file contents are excluded.
2. **System 1:** receives that machine evidence directly in bounded candidate
   contexts, not an agent's interpretation. It selects readiness, evidence gap
   and question categories. Every Choice ends with the literal `fallout` option.
   Noul sufficiency/coverage predicates and advisory scores are retained.
3. **Safety interpreter:** applies preservation, complete-inspection, active-use
   and supported-action rules outside the model. A model cannot create a cleanup
   command or override database/log/model protection. A supported model answer
   with an unavailable adapter is an explicit review item, not an executable row.
4. **Reporter:** automatically writes a mode-0600 Markdown handoff and persistent
   checklist. Separate tables show ready-for-approval candidates, protected
   resources, fallout/evidence/adapter failures, and previously verified changes.
   The full packet/review/drive-space tables remain attached.
5. **Agent:** analyse that final report and hand it back to the owner. Explain
   unresolved outcomes and any disagreement transparently; do not replace them
   with a new classification or manually collected facts. The owner decides
   approval, further investigation or process improvement.

## Bounded additional evidence and failures

The runner may make one larger metadata-only probe when System 1 requests a
specific content gap on a truncated filesystem survey. It submits another packet
only if observations changed. Unknown ownership/recovery, volume contents that
cannot be inspected through existing read-only APIs, conflicting answers and
unsupported actions go to review rather than improvised inspection or cleanup.
When a requested probe is unavailable or exhausted, the open evidence item is
explicitly routed to process review with that limitation. The agent does not
silently take over evidence collection.

Default bounds are 64 contexts per section, 512 metadata entries per path and
10 seconds per native command. A content expansion is at most 8x the initial
entry limit. `--max-resources`, `--entry-limit` and `--timeout` can explicitly
adjust these bounded budgets. Omitted/inaccessible resources remain visible
unclassified or unmeasured review items; a timeout is never zero usage. Database
volumes are not mounted merely to finish the report. Collection is targeted and
bounded, not a promise to account for every byte on a drive.

External drives use individual child measurements, with a per-drive measurement
budget of twice the native timeout. Known OS volume metadata directories are
preserved without inspection; hidden user directories are not blanket-skipped.
One unreadable child never discards readable siblings. Coverage tables expose
measured, protected, inaccessible and budget-skipped paths separately from
candidate classification; none is silently treated as zero.

An unavailable gateway produces process-review items and a partial report.
After the first transport failure in an invocation, other sections keep
collecting evidence without repeating the same unavailable gateway call.
Malformed or partial responses are explicit failures. There is no upstream or
agent-decision fallback. Exit code 2 signals outstanding review/failure work;
the saved report still exists and should be handed back, not hidden or retried.

## Resume and approval

```bash
python3 <plugin>/scripts/system_maintenance.py recover --resume SESSION_ID
```

Resume re-collects native facts at the previously used inspection depth, compares
a semantic collection signature (timestamps/filenames alone are not new facts),
and reuses unchanged classifications—including failures. A retry requires changed
source observations or `--recovery-evidence /absolute/recovery.json`. Original
failures remain in the process-review queue after recovery. Existing executed or
interrupted cleanup journals are never overwritten or replayed by discovery.
Owner-kept/deferred sections are not reopened by resume, and retained candidate
IDs remain preservation selectors even if other native observations change.
An interrupted decision request becomes an explicit review on resume, not an
empty successful report. When an audit expires but native facts/policy/rubric
are identical, the runner links the original classification to a fresh audit
without re-calling System 1; any expired exact-plan approval is invalidated.

`--sections caches models ...` selects a narrower investigation at creation.
`--keep` records exact preservation selectors. A resumed session cannot silently
change its scope or preservation policy. Numerical scores remain advisory.

The report's ready rows still require the separate [session approval flow](sessions.md#plan-owner-approval-and-execution).
Select exact candidate IDs, present the generated plan, record the owner's actual
approval, then run that exact plan. Unresolved candidates are not selectable.
An unrelated fallout row does not block a separately established safe selection,
but a failed shared decision response blocks all affected rows. Existing native
resource preflight remains mandatory immediately before approved mutation.

The runner has no cleanup or approval flags. If a requested cleanup type has no
supported adapter, keep it as review work; do not bypass the session with shell
commands to make the automatic report appear complete.
