#!/usr/bin/env python3
"""One invocation: native evidence → System 1 → owner handoff. Never cleanup."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
import time
import urllib.error

import storage
import storage_collectors as collectors
import storage_session as sessions

DEFAULT_GOAL = "Discover reclaimable space across local drives; preserve databases, logs, installed models and active applications. Report exact candidates and exceptions for owner approval."


def source_signature(bundle, policy):
    value = copy.deepcopy(bundle)
    value["report"].pop("created", None)
    value["report"].pop("id", None)
    return storage.digest({"collection": value, "policy": policy, "question_schema": sessions.QUESTION_SCHEMA})


def install_collection(state, session, bundle):
    """Machine-generated evidence goes directly to the existing session gates."""
    name = bundle["section"]
    report = copy.deepcopy(bundle["report"])
    report["id"] = sessions.identifier("report")
    artifact = storage.save_document(state, "evidence", sessions.identifier("collection"), bundle)
    storage.save_document(state, "reports", report["id"], report)
    observations = {"candidates": []}
    for row in bundle["rows"]:
        facts = copy.deepcopy(row["facts"])
        facts["evidence_refs"] = [str(artifact)]
        observations["candidates"].append({"id": row["candidate"]["id"], "facts": facts})
    sessions.attach(session, name, report, observations)
    section = session["sections"][name]
    section.update(automatic=True, collection_artifact=str(artifact), collection_signature=source_signature(bundle, session["policy"]), candidate_outcomes={})
    by_id = {r["candidate"]["id"]: r for r in bundle["rows"]}
    for row in section["rows"]:
        row["machine_observations"] = copy.deepcopy(by_id[row["candidate"]["id"]]["machine_observations"])
        # All observed candidates reach the model, including protected/unknown rows.
        # Preservation rules still override its interpretation, outside the model.
        row["disposition"] = "pending"
        row.pop("reason", None)
    return section


def add_notices(session, bundle):
    for notice in bundle["notices"]:
        item = sessions.review(session, bundle["section"], notice["kind"], notice["detail"], ["Native evidence within a supported inspection boundary"])
        # Unknown omitted resources do not permit deletion of themselves, nor
        # block independent fully observed candidates. They stay visible review work.
        item["blocking"] = not bool(bundle["rows"])
        item["process_improvement"] = True


def refresh_equivalent_audit(state, session, bundle):
    """Revalidate fresh identical facts without rerunning an unchanged rubric.

    The old classification remains immutable and linked; expired owner approval
    is not transferred to the new exact plan/evidence binding.
    """
    section = session["sections"][bundle["section"]]
    prior = copy.deepcopy(section)
    install_collection(state, session, bundle)
    current = session["sections"][bundle["section"]]
    packet = sessions.packet_for(session, bundle["section"])
    old_attempt = next(a for a in prior["attempts"] if a["packet_id"] == prior["decision"]["packet_id"])
    attempt = {"packet_id": packet["id"], "packet": packet, "created": time.time(), "outcome": "classified",
               "response": copy.deepcopy(old_attempt["response"]), "gateway": old_attempt.get("gateway"), "latency_ms": 0,
               "semantic_cache_from": old_attempt["packet_id"], "reason": "Native facts, policy and rubric unchanged; fresh audit after evidence expiry. Owner approval invalidated."}
    current["attempts"].append(attempt)
    current["decision"] = {"packet_id": packet["id"], "results": copy.deepcopy(prior["decision"]["results"])}
    current["candidate_outcomes"] = prior["candidate_outcomes"]
    current["status"] = "awaiting_approval" if prior["status"] == "approved" else prior["status"]


def finish_report(state, session, rt):
    session["latest_volumes"] = rt.volumes()
    session["latest_measured_at"] = time.time()
    session["runner"]["phase"] = "handoff_ready"
    session["runner"]["cleanup_executed"] = False
    sessions.save(state, session)
    text = render_handoff(session)
    path = storage.save_text(state, "reports", session["id"] + f"-handoff-{session['revision']}", text + "\n")
    session["runner"]["handoff_path"] = str(path)
    sessions.save(state, session)
    return path, text


def render_handoff(session):
    eligible, retained, exceptions, completed = [], [], [], []
    for name, section in session["sections"].items():
        for row in section["rows"]:
            candidate = row["candidate"]
            outcome = section.get("candidate_outcomes", {}).get(candidate["id"], {})
            status = outcome.get("outcome", section["status"])
            reason = outcome.get("reason", "No valid classification; inspect the review queue")
            model = outcome.get("model", {})
            display = [name, candidate["id"], candidate["item"], storage.gib(candidate.get("size")), status, model.get("readiness", "not established"), reason]
            if section["status"] == "verified":
                display[4] = "previously verified"
                completed.append(display)
            elif section.get("journal") or section.get("receipts") or any(r["section"] == name and r["kind"] in {"execution_failure", "interrupted_execution"} and r["status"] == "open" for r in session["reviews"]):
                display[4] = "execution reconciliation required"
                display[6] = "Existing execution evidence is unresolved; discovery cannot replay or replace it"
                exceptions.append(display)
            elif section.get("owner_disposition"):
                display[4] = section["status"]
                display[6] = section.get("reason", "Owner retained or deferred this section")
                retained.append(display)
            elif status == "supported":
                eligible.append(display)
            elif status == "kept":
                retained.append(display)
            else:
                exceptions.append(display)
    lines = ["# Automatic space-recovery handoff", "", f"Session: `{session['id']}`", "", session["goal"], "",
             "**READ-ONLY: this invocation performed no cleanup, approval, process restart, database startup or helper-container operation.**",
             "Evidence came from native collectors directly to System 1. The agent did not author observations or pre-classify findings. Scores are advisory; explicit rubric choices and independent safety checks determine the report."]
    coverage = []
    for name, section in session["sections"].items():
        if name != "closeout":
            measured = section.get("report", {}).get("measurements", [])
            unmeasured = [m for m in measured if m.get("bytes") is None]
            protected = sum(m.get("status", "").startswith("Protected OS") for m in unmeasured)
            skipped = sum(m.get("status", "").startswith("not_run") for m in unmeasured)
            coverage.append([name, len(section["rows"]), len(measured)-len(unmeasured), protected, len(unmeasured)-protected-skipped, skipped, section["status"]])
    lines += ["", "## Collection coverage", "", storage.table(["Section", "Candidates observed", "Measured paths", "OS-protected paths", "Unmeasured paths", "Budget-skipped paths", "State"], coverage)]
    headers = ["Section", "Candidate", "Resource", "Measured contents", "Safety outcome", "System 1 choice", "Reason"]
    for title, rows in (("Ready to present for exact owner approval", eligible), ("Retain / protected", retained), ("Fallout, missing evidence or unsupported action", exceptions), ("Previously approved verified changes", completed)):
        lines += ["", "## " + title, "", storage.table(headers, rows)]
    lines += ["", "A ready row is a recommendation, not permission. Use the persisted session's plan → explicit owner approval → run flow. Unselected, protected, unmeasured and fallout resources stay untouched.",
              "", sessions.render(session)]
    return "\n".join(lines)


def recover(rt, state, goal=DEFAULT_GOAL, sections=collectors.SECTIONS, keep=(), resume=None, collector=None, caller=None, recovery=None):
    sessions.require(sections and set(sections) <= set(collectors.SECTIONS), "Choose supported collector sections")
    collector = collector or collectors.Collector(rt)
    gateway_failure = []

    def decision_call(payload):
        if gateway_failure:
            raise OSError("Gateway was unavailable earlier in this invocation; no automatic retry or substitute decision")
        try:
            return (caller or sessions.jev_request)(payload)
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            gateway_failure.append(type(exc).__name__)
            raise
    if resume:
        session = sessions.load_session(state, resume)
        sessions.require(session.get("runner", {}).get("version") == 1, "Resume an automatic runner session; manual sessions keep their separate workflow")
        sessions.require(not keep or list(keep) == session["policy"]["keep"], "Resume keeps the original preservation policy; start a new session for changed scope")
        sessions.require(set(sections) <= set(session["sections"]), "Resume cannot silently add sections")
    else:
        session = sessions.new_session(rt, goal, [*sections, "closeout"], keep)
        session["runner"] = {"version": 1, "phase": "collecting", "cleanup_executed": False}
        sessions.save(state, session)
    with sessions.session_lock(state, session["id"]):
        # Re-read under the one-writer lock after a resumed process joins.
        session = sessions.load_session(state, session["id"])
        for name in sections:
            section = session["sections"][name]
            if section.get("owner_disposition"):
                continue
            if section["status"] in {"executing", "verified"} or section.get("receipts"):
                if section["status"] == "executing":
                    sessions.review(session, name, "interrupted_execution", "Reconcile the existing cleanup journal; automatic discovery will not replay or replace it", ["Reconciliation evidence"])
                continue
            try:
                bundle = collector.collect(name)
                previous_expansions = [r["candidate"]["id"] for r in section["rows"] if r.get("machine_observations", {}).get("probe_level") == 1]
                if previous_expansions:
                    bundle = collector.expand(bundle, previous_expansions) or bundle
                signature = source_signature(bundle, session["policy"])
                previous = section.get("collection_signature")
                if previous == signature and recovery is None:
                    # No new facts: reuse the result, including a failed outcome.
                    # A new timestamp or a fresh report filename is not recovery.
                    if section["attempts"] and section["attempts"][-1]["outcome"] == "started":
                        if not any(r["section"] == name and r["kind"] == "interrupted_decision" and r["status"] == "open" for r in session["reviews"]):
                            item = sessions.review(session, name, "interrupted_decision", "Previous System 1 request was interrupted; no decision or automatic retry. Provide changed evidence/recovery conditions.", ["Changed source observations or recovery evidence"])
                            item["process_improvement"] = True
                    elif section.get("decision") and rt.now - section["report"]["created"] > storage.MAX_PLAN_AGE:
                        refresh_equivalent_audit(state, session, bundle)
                    continue
                section = install_collection(state, session, bundle)
                sessions.save(state, session)
                sessions.triage(session, name, caller=decision_call, recovery=recovery, persist=lambda: sessions.save(state, session))
                sessions.save(state, session)
                # A single additional metadata probe is allowed only for a
                # specific content gap and only when it adds actual observations.
                requested = [cid for cid, value in section.get("candidate_outcomes", {}).items()
                             if value["outcome"] == "more_evidence" and value["model"]["gap"] == "content"]
                if requested:
                    expanded = collector.expand(bundle, requested)
                    if expanded and source_signature(expanded, session["policy"]) != signature:
                        section = install_collection(state, session, expanded)
                        sessions.save(state, session)
                        sessions.triage(session, name, caller=decision_call, recovery=recovery, persist=lambda: sessions.save(state, session))
                        bundle = expanded
                for cid, value in section.get("candidate_outcomes", {}).items():
                    if value["outcome"] == "more_evidence":
                        for item in session["reviews"]:
                            if item["section"] == name and item["candidate"] == cid and item["status"] == "open" and item["kind"] == "more_evidence":
                                item.update(route="review", process_improvement=True)
                                item["detail"] += "; No further supported automatic evidence probe remains. Review the collector/rubric or provide an authoritative source; no agent-authored substitute."
                add_notices(session, bundle)
            except Exception as exc:
                # A failed collector/packet never becomes an empty successful scan.
                sessions.review(session, name, "runner_failure", f"Automatic section stopped: {type(exc).__name__}: {exc}", ["Correct collector/packet evidence; no agent-invented replacement"])
            sessions.save(state, session)
        path, text = finish_report(state, session, rt)
    return session, path, text


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir")
    parser.add_argument("--goal", default=DEFAULT_GOAL)
    parser.add_argument("--sections", nargs="+", choices=collectors.SECTIONS)
    parser.add_argument("--resume", help="Explicit automatic session ID; unchanged failures are not retried")
    parser.add_argument("--keep", action="append", default=[])
    parser.add_argument("--max-resources", type=int, default=64, help="Maximum rubric contexts per section; omitted resources become visible review items")
    parser.add_argument("--timeout", type=int, default=10, help="Per-native-command timeout, 1–30 seconds")
    parser.add_argument("--entry-limit", type=int, default=512, help="Metadata entries per initial path probe, 32–4096; at most one 8x expansion")
    parser.add_argument("--recovery-evidence", help="Existing artifact documenting changed recovery conditions; never an approval")
    args = parser.parse_args(argv)
    try:
        sessions.require(1 <= args.max_resources <= 64 and 1 <= args.timeout <= 30 and 32 <= args.entry_limit <= 4096, "Unsupported collection budget")
        rt, state = storage.Runtime(), storage.state_root(args.state_dir)
        sections = args.sections
        if sections is None:
            sections = [name for name in sessions.load_session(state, args.resume)["sections"] if name != "closeout"] if args.resume else list(collectors.SECTIONS)
        collector = collectors.Collector(rt, args.max_resources, args.timeout, args.entry_limit)
        session, path, text = recover(rt, state, args.goal, sections, args.keep, args.resume, collector,
                                      recovery=sessions.evidence_file(args.recovery_evidence) if args.recovery_evidence else None)
        print(text)
        print(f"\nHandoff report: {path}")
        # A report with outstanding exceptions is a visible partial outcome,
        # not a silent successful recovery. It is still available for handoff.
        return 2 if any(r["status"] == "open" for r in session["reviews"]) else 0
    except Exception as exc:
        print(f"Blocked: automatic discovery did not complete: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
