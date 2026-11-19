#!/usr/bin/env python3
"""Bounded storage reports and explicitly selected, native-first cleanup."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

SCHEMA = 1
MAX_PLAN_AGE = 24 * 60 * 60
MAX_PATH_ENTRIES = 50_000
ADAPTERS = {"ollama-model", "docker-build-cache", "docker-unused-images", "path"}


class MaintenanceError(Exception):
    """An unmet precondition; never permission to widen the cleanup."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def gib(value):
    if value is None:
        return "Unmeasured"
    if abs(value) >= 2**30:
        return f"{value / 2**30:,.2f} GiB"
    if abs(value) >= 2**20:
        return f"{value / 2**20:,.1f} MiB"
    return f"{value:,} B"


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def table(headers, rows):
    return "\n".join([
        "| " + " | ".join(map(cell, headers)) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
        *("| " + " | ".join(map(cell, row)) + " |" for row in rows),
    ])


def parse_size(value):
    match = re.match(r"^\s*(\d+(?:\.\d+)?)\s*(B|[KMGTPE]i?B)\b", str(value), re.I)
    if not match:
        return None
    number, unit = match.groups()
    unit = unit.upper()
    power = 0 if unit == "B" else "KMGTPE".index(unit[0]) + 1
    return int(float(number) * (1024 if "I" in unit else 1000) ** power)


class Runtime:
    def __init__(self, home=None, now=None):
        self.home = Path(home or Path.home()).resolve()
        self.now = time.time() if now is None else now

    def command(self, args, timeout=10, env=None):
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            raise MaintenanceError(f"{args[0]} timed out after {timeout}s") from exc
        except OSError as exc:
            raise MaintenanceError(f"{args[0]} unavailable: {exc}") from exc
        if result.returncode:
            message = (result.stderr or result.stdout).strip()[:500]
            raise MaintenanceError(f"{args[0]} failed ({result.returncode}): {message}")
        return result.stdout

    def ollama(self, endpoint, route, payload=None):
        endpoint = local_ollama(endpoint)
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(endpoint + "/api/" + route, data=data,
                                         headers={"Content-Type": "application/json"})
        try:
            # Local API traffic must not be sent through a configured HTTP proxy.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=10) as response:
                return json.load(response)
        except (OSError, ValueError) as exc:
            raise MaintenanceError(f"Local Ollama {route} unavailable: {exc}") from exc

    def volumes(self, paths=None):
        roots = paths
        if roots is None:
            roots = [Path("/System/Volumes/Data") if Path("/System/Volumes/Data").exists() else self.home]
            if Path("/Volumes").is_dir():
                roots += [p for p in Path("/Volumes").iterdir() if not p.is_symlink() and p.is_mount()]
        result, seen = [], set()
        for path in roots:
            try:
                device = path.stat().st_dev
                info = {}
                if sys.platform == "darwin" and shutil.which("diskutil"):
                    try:
                        info = plistlib.loads(self.command(["diskutil", "info", "-plist", str(path)], timeout=3).encode())
                    except (MaintenanceError, ValueError, plistlib.InvalidFileException):
                        pass
                # APFS volumes can share one pool; Recovery is not a second disk.
                group = ("apfs", info["APFSContainerReference"]) if info.get("APFSContainerReference") else ("device", device)
                if group in seen:
                    continue
                seen.add(group)
                fs = os.statvfs(path)
                result.append({"path": str(path), "device": device,
                               "total": fs.f_blocks * fs.f_frsize,
                               "free": fs.f_bavail * fs.f_frsize,
                               "external": info.get("Internal") is False,
                               "status": "measured; drive location unknown" if not info and str(path).startswith("/Volumes/") else "measured"})
            except OSError as exc:
                result.append({"path": str(path), "error": str(exc), "external": False})
        return result

    def no_open_files(self, path):
        args = ["lsof", "-nP"] + (["+D", str(path)] if path.is_dir() else [str(path)])
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MaintenanceError(f"Open-file check unavailable: {exc}") from exc
        if result.stderr.strip() or result.returncode not in (0, 1):
            raise MaintenanceError("Open-file check incomplete; retain this path")
        if result.stdout.strip():
            raise MaintenanceError("Files are open in this path; retain it until use has stopped")


def local_ollama(value=None):
    value = value or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    if "://" not in value:
        value = "http://" + value
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise MaintenanceError("This tool supports only a loopback Ollama server")
    try:
        port = parsed.port or 11434
    except ValueError as exc:
        raise MaintenanceError("Invalid local Ollama port") from exc
    host = "[::1]" if parsed.hostname == "::1" else parsed.hostname
    return f"http://{host}:{port}"


def model_catalog(rt, endpoint):
    return {m["name"]: m["digest"] for m in rt.ollama(endpoint, "tags")["models"]}


def docker_context(rt):
    if os.environ.get("DOCKER_HOST"):
        raise MaintenanceError("DOCKER_HOST overrides context selection; use a local named context first")
    name = rt.command(["docker", "context", "show"]).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise MaintenanceError("Unsupported Docker context name")
    endpoint = json.loads(rt.command(["docker", "context", "inspect", name,
                                      "--format", "{{json .Endpoints.docker.Host}}"])).strip()
    if not endpoint.startswith("unix:///"):
        raise MaintenanceError("This tool supports only local Unix-socket Docker contexts")
    return {"name": name, "endpoint": endpoint}


def docker_rows(rt, context):
    raw = rt.command(["docker", "--context", context["name"], "system", "df", "--format", "{{json .}}"])
    try:
        return {row["Type"]: row for row in (json.loads(line) for line in raw.splitlines() if line.strip())}
    except (KeyError, ValueError) as exc:
        raise MaintenanceError("Docker returned an unsupported disk-usage format") from exc


def candidate_id(adapter, selector):
    return adapter.upper() + "-" + digest(selector)[:10]


def measured_path(rt, path, timeout):
    path = Path(path).expanduser().absolute()
    if not path.exists():
        return {"path": str(path), "bytes": None, "status": "missing"}
    target = path.resolve()
    try:
        raw = rt.command(["du", "-skx", str(target)], timeout=timeout)
        size = int(raw.split()[0]) * 1024
        return {"path": str(path), "resolved": str(target), "bytes": size,
                "status": "external link" if path.is_symlink() else "measured"}
    except (MaintenanceError, ValueError, IndexError) as exc:
        return {"path": str(path), "resolved": str(target), "bytes": None,
                "status": "unmeasured", "detail": str(exc)}


def native_store_marker(names):
    return (("blobs" in names and bool({"manifests", "manifests-v2"} & names))
            or "Docker.raw" in names or "device_set.plist" in names)


def guard_path(rt, value):
    supplied = Path(value).expanduser().absolute()
    if supplied.is_symlink():
        raise MaintenanceError("Inspect and approve the resolved target explicitly; this path is a symlink")
    try:
        path = supplied.resolve(strict=True)
    except OSError as exc:
        raise MaintenanceError(f"Path unavailable: {exc}") from exc
    protected = [Path("/"), Path("/System"), Path("/Library"), Path("/Users"),
                 Path("/Volumes"), Path("/Applications"), Path("/private"), Path("/var"),
                 Path("/tmp").resolve(), Path("/private/tmp"), Path("/private/var"),
                 Path("/private/var/tmp"), Path(tempfile.gettempdir()).resolve(), rt.home,
                 rt.home / "Library/Application Support/System Maintenance",
                 rt.home / ".local/state/system-maintenance",
                 Path(__file__).resolve().parents[1]]
    managed = [rt.home / ".ollama", rt.home / "Library/Containers/com.docker.docker",
               rt.home / "Library/Developer/CoreSimulator", Path("/Library/Developer/CoreSimulator")]
    for root in protected:
        if path == root or root.is_relative_to(path):
            raise MaintenanceError(f"Protected root or ancestor: {path}")
    for root in managed:
        root = root.resolve()
        if path.is_relative_to(root) or root.is_relative_to(path):
            raise MaintenanceError("Managed model/container/simulator storage requires its native owner command")
    if path.is_mount():
        raise MaintenanceError("A whole mounted volume cannot be a path-cleanup target")
    for ancestor in [path, *path.parents]:
        if ancestor.is_dir():
            try:
                if native_store_marker({p.name for p in ancestor.iterdir()}):
                    raise MaintenanceError("Managed store contents require their native owner command")
            except PermissionError as exc:
                raise MaintenanceError(f"Cannot establish path ownership: {exc}") from exc
    return path


def path_snapshot(rt, value):
    path = guard_path(rt, value)
    root_stat = path.lstat()
    rows, stack = [], [path]
    while stack:
        node = stack.pop()
        st = node.lstat()
        rel = str(node.relative_to(path))
        link = os.readlink(node) if stat.S_ISLNK(st.st_mode) else None
        rows.append([rel, stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns, link])
        if len(rows) > MAX_PATH_ENTRIES:
            raise MaintenanceError("Path exceeds the bounded fingerprint limit; narrow the inspected target")
        if stat.S_ISDIR(st.st_mode):
            children = list(node.iterdir())
            if native_store_marker({p.name for p in children}):
                raise MaintenanceError("Path contains managed storage; use its native owner command")
            stack.extend(children)
    return {"path": str(path), "device": root_stat.st_dev, "inode": root_stat.st_ino,
            "tree": digest(sorted(rows)), "entries": len(rows)}


def collect_ollama(rt, report):
    endpoint = local_ollama()
    models = rt.ollama(endpoint, "tags")["models"]
    loaded = {m.get("name", m.get("model")) for m in rt.ollama(endpoint, "ps").get("models", [])}
    report["catalogs"]["ollama"] = {m["name"]: m["digest"] for m in models}
    report["ollama_endpoint"] = endpoint
    for model in sorted(models, key=lambda m: m["name"]):
        name = model["name"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", name):
            raise MaintenanceError("Unsupported model name in local catalog")
        report["candidates"].append({
            "id": candidate_id("ollama-model", name), "item": name, "category": "Ollama model",
            "location": endpoint, "size": model.get("size"), "reclaimable": None,
            "status": "blocked" if name in loaded else "review",
            "reason": "Loaded model; stop needs separate approval" if name in loaded
                      else "Installed model size; shared files can reduce actual recovery",
            "action": {"adapter": "ollama-model", "model": name, "endpoint": endpoint,
                       "expected": model["digest"]},
        })
    report["notes"].append("Ollama rows are installed models, not evidence of disuse. Raw orphan/blob deletion is unsupported.")


def collect_docker(rt, report):
    context = docker_context(rt)
    rows = docker_rows(rt, context)
    for kind, adapter, title in [("Build Cache", "docker-build-cache", "Unused Docker build cache"),
                                  ("Images", "docker-unused-images", "Docker images unused by any container")]:
        row = rows.get(kind)
        if row is None:
            raise MaintenanceError(f"Docker omitted {kind} disk usage")
        reclaimable = parse_size(row.get("Reclaimable"))
        size = parse_size(row.get("Size"))
        report["measurements"].append({"path": f"Docker {kind}", "resolved": context["name"],
                                       "bytes": size, "status": "native estimate"})
        if reclaimable is None:
            report["checks"].append({"area": "docker", "status": "unmeasured", "detail": f"Cannot parse {kind} reclaimable size"})
        elif reclaimable > 0:
            report["candidates"].append({
                "id": candidate_id(adapter, context), "item": title, "category": "Docker",
                "location": context["name"], "size": size, "reclaimable": reclaimable,
                "status": "review", "reason": "Native reclaimable estimate; shared image layers are not additive",
                "action": {"adapter": adapter, "context": context, "kind": kind, "expected": digest(row)},
            })
    report["notes"].append("Docker volumes and databases are excluded from cleanup.")


def audit(rt, scopes, paths=(), timeout=10, external_limit=12):
    report = {"schema": SCHEMA, "created": rt.now, "volumes": rt.volumes(),
              "measurements": [], "candidates": [], "catalogs": {}, "checks": [], "notes": []}
    if "system" in scopes:
        for relative in ["Library/Caches", "Library/Developer/CoreSimulator/Devices",
                         "Library/Developer/Xcode/iOS DeviceSupport", "Library/Developer/Xcode/Archives",
                         ".codex", ".cache"]:
            report["measurements"].append(measured_path(rt, rt.home / relative, timeout))
        for path in dict.fromkeys(["/private/tmp", "/private/var/tmp", tempfile.gettempdir()]):
            report["measurements"].append(measured_path(rt, path, timeout))
        raw = rt.home / "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"
        if raw.is_file():
            report["measurements"].append({"path": str(raw), "bytes": raw.stat().st_blocks * 512,
                                           "status": "allocated disk-image space"})
    for area, collector in [("docker", collect_docker), ("ollama", collect_ollama)]:
        if area not in scopes:
            continue
        try:
            collector(rt, report)
            report["checks"].append({"area": area, "status": "observed", "detail": "Local native inventory available"})
        except (MaintenanceError, KeyError, ValueError) as exc:
            report["checks"].append({"area": area, "status": "unavailable", "detail": str(exc)})
    if "external" in scopes:
        for volume in report["volumes"]:
            if not volume.get("external"):
                continue
            try:
                children = sorted(p for p in Path(volume["path"]).iterdir() if not p.name.startswith("."))
                for child in children[:external_limit]:
                    report["measurements"].append(measured_path(rt, child, timeout))
                if len(children) > external_limit:
                    report["notes"].append(f"{volume['path']}: first {external_limit} entries inspected; narrow with --path for more.")
            except OSError as exc:
                report["checks"].append({"area": volume["path"], "status": "unmeasured", "detail": str(exc)})
    for supplied in dict.fromkeys(paths):
        measured = measured_path(rt, supplied, timeout)
        report["measurements"].append(measured)
        row = {"id": candidate_id("path", str(Path(supplied).expanduser().absolute())),
               "item": str(supplied), "category": "Explicit path", "location": measured.get("resolved", str(supplied)),
               "size": measured["bytes"], "reclaimable": None, "status": "review",
               "reason": "Explicitly inspected path; owner must choose whether it is still wanted"}
        try:
            snapshot = path_snapshot(rt, supplied)
            rt.no_open_files(Path(snapshot["path"]))
            row["action"] = {"adapter": "path", "path": snapshot["path"], "expected": snapshot}
        except (MaintenanceError, OSError) as exc:
            row.update(status="blocked", reason=str(exc))
        report["candidates"].append(row)
    report["notes"].append("Sizes can overlap; do not sum parent directories, linked targets, models or image layers.")
    return report


def action_text(action):
    adapter = action.get("adapter")
    if adapter == "ollama-model":
        return "ollama rm " + action["model"]
    if adapter.startswith("docker-"):
        tail = "builder prune --all --force" if adapter == "docker-build-cache" else "image prune --all --force"
        return f"docker --context {action['context']['name']} {tail}"
    return "Verify exact path → quarantine → purge"


def render_report(report):
    sections = ["## Disk capacity", table(["Volume", "Capacity", "Free", "Status"], [
        [v["path"], gib(v.get("total")), gib(v.get("free")), v.get("error", v.get("status", "measured"))]
        for v in report["volumes"]])]
    if report["measurements"]:
        sections += ["## Storage breakdown", table(["Location", "Size", "Status / resolved target"], [
            [m["path"], gib(m["bytes"]), m["status"] + (": " + m["detail"] if m.get("detail") else "")
             + (" → " + m["resolved"] if m.get("resolved") not in (None, m["path"]) else "")]
            for m in report["measurements"]])]
    sections += ["## Cleanup candidates — pending owner selection", table(
        ["ID", "Item", "Size", "Estimated recovery", "Action", "Status / evidence"], [
            [r["id"], r["item"], gib(r.get("size")), gib(r.get("reclaimable")),
             action_text(r["action"]) if "action" in r else "Retain",
             r["status"] + ": " + r["reason"]] for r in report["candidates"]])]
    if report["checks"]:
        sections += ["## Checks", table(["Area", "Status", "Evidence / limitation"], [
            [r["area"], r["status"], r["detail"]] for r in report["checks"]])]
    sections += ["\n".join(dict.fromkeys(report["notes"]))]
    return "\n\n".join(sections)


def validate_action(action):
    adapter = action.get("adapter")
    if adapter not in ADAPTERS:
        raise MaintenanceError("Unknown cleanup adapter")
    if adapter == "ollama-model":
        local_ollama(action["endpoint"])
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", action["model"]):
            raise MaintenanceError("Invalid model selector")
        if not re.fullmatch(r"[a-f0-9]{64}", action["expected"]):
            raise MaintenanceError("Invalid model fingerprint")
    elif adapter.startswith("docker-"):
        context = action["context"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", context["name"]):
            raise MaintenanceError("Invalid Docker context")
        if not context["endpoint"].startswith("unix:///"):
            raise MaintenanceError("Remote Docker cleanup is outside this tool")
        expected_kind = "Build Cache" if adapter == "docker-build-cache" else "Images"
        if action["kind"] != expected_kind:
            raise MaintenanceError("Docker cleanup kind mismatch")


def prepare_plan(rt, report, ids):
    if report.get("schema") != SCHEMA or not 0 <= rt.now - report["created"] <= MAX_PLAN_AGE:
        raise MaintenanceError("Report expired or unsupported; audit again")
    by_id = {r["id"]: r for r in report["candidates"]}
    if not ids or len(ids) != len(set(ids)):
        raise MaintenanceError("Select explicit, unique candidate IDs")
    items = []
    for selected in ids:
        row = by_id.get(selected)
        if row is None or row["status"] == "blocked" or "action" not in row:
            raise MaintenanceError(f"Unknown or blocked candidate: {selected}")
        validate_action(row["action"])
        items.append({k: row[k] for k in ("id", "item", "location", "size", "action")})
    paths = [Path(r["action"]["path"]) for r in items if r["action"]["adapter"] == "path"]
    if len(paths) != len(set(paths)):
        raise MaintenanceError("Duplicate resolved path selections must be reduced to one item")
    if any(a != b and (a.is_relative_to(b) or b.is_relative_to(a)) for a in paths for b in paths):
        raise MaintenanceError("Overlapping parent/child path selections must be reviewed separately")
    plan = {"schema": SCHEMA, "created": rt.now, "report": report.get("id"), "items": items,
            "catalogs": report["catalogs"], "ollama_endpoint": report.get("ollama_endpoint")}
    plan["id"] = "plan-" + digest(plan)[:20]
    return plan


def validate_plan(plan, approval, now):
    identity = plan.get("id")
    body = {k: v for k, v in plan.items() if k != "id"}
    if identity != "plan-" + digest(body)[:20]:
        raise MaintenanceError("Plan content changed; prepare a new plan")
    if approval != identity:
        raise MaintenanceError("Explicit approval must match the reviewed plan ID")
    if plan.get("schema") != SCHEMA or not 0 <= now - plan["created"] <= MAX_PLAN_AGE:
        raise MaintenanceError("Plan expired or unsupported; audit again")
    if not plan["items"] or len({r["id"] for r in plan["items"]}) != len(plan["items"]):
        raise MaintenanceError("Plan has no unique selected items")
    for row in plan["items"]:
        validate_action(row["action"])


def preflight(rt, plan):
    docker = None
    model_actions = [r["action"] for r in plan["items"] if r["action"]["adapter"] == "ollama-model"]
    if model_actions:
        endpoint = local_ollama(plan["ollama_endpoint"])
        if any(a["endpoint"] != endpoint for a in model_actions):
            raise MaintenanceError("Ollama endpoint changed")
        if model_catalog(rt, endpoint) != plan["catalogs"].get("ollama"):
            raise MaintenanceError("Ollama catalog changed; audit again")
        loaded = {m.get("name", m.get("model")) for m in rt.ollama(endpoint, "ps").get("models", [])}
        for action in model_actions:
            if plan["catalogs"]["ollama"].get(action["model"]) != action["expected"]:
                raise MaintenanceError("Model fingerprint changed")
            if action["model"] in loaded:
                raise MaintenanceError(f"Model is loaded; retain {action['model']}")
    for row in plan["items"]:
        action = row["action"]
        if action["adapter"].startswith("docker-"):
            if docker is None:
                context = docker_context(rt)
                docker = (context, docker_rows(rt, context))
            context, rows = docker
            if action["context"] != context or digest(rows.get(action["kind"])) != action["expected"]:
                raise MaintenanceError("Docker context or usage changed; audit again")
        elif action["adapter"] == "path":
            if path_snapshot(rt, action["path"]) != action["expected"]:
                raise MaintenanceError("Path contents or identity changed; audit again")
            rt.no_open_files(Path(action["path"]))


def remove_ollama(rt, action, plan_id):
    env = os.environ.copy()
    env["OLLAMA_HOST"] = local_ollama(action["endpoint"])
    output = rt.command(["ollama", "rm", action["model"]], timeout=120, env=env)
    return {"detail": output.strip() or "Native model removal completed"}


def prune_docker(rt, action, plan_id):
    if docker_context(rt) != action["context"]:
        raise MaintenanceError("Docker context changed before cleanup")
    command = "builder" if action["adapter"] == "docker-build-cache" else "image"
    output = rt.command(["docker", "--context", action["context"]["name"], command,
                         "prune", "--all", "--force"], timeout=120)
    summary = next((line.strip() for line in reversed(output.splitlines())
                    if re.match(r"\s*Total(?: reclaimed space)?\s*:", line, re.I)), "Native prune completed")
    return {"detail": summary, "native_output": output[-20_000:]}


def purge_path(rt, action, plan_id):
    path = guard_path(rt, action["path"])
    if path_snapshot(rt, path) != action["expected"]:
        raise MaintenanceError("Path changed before cleanup")
    rt.no_open_files(path)
    quarantine = path.with_name(f".system-maintenance-{plan_id}-{digest(str(path))[:8]}")
    if quarantine.exists() or quarantine.is_symlink():
        raise MaintenanceError(f"Quarantine already exists: {quarantine}")
    path.rename(quarantine)
    try:
        after_move = path_snapshot(rt, quarantine)
        if after_move["tree"] != action["expected"]["tree"]:
            raise MaintenanceError("Contents changed while quarantining")
        rt.no_open_files(quarantine)
    except Exception:
        if not path.exists() and not path.is_symlink():
            quarantine.rename(path)
        raise
    try:
        if quarantine.is_dir():
            def onerror(function, target, exc_info):
                # macOS may remove AppleDouble companions with their parent file.
                if not isinstance(exc_info[1], FileNotFoundError):
                    raise exc_info[1]
            shutil.rmtree(quarantine, onerror=onerror)
        else:
            quarantine.unlink()
    except OSError as exc:
        raise MaintenanceError(f"Purge incomplete; retained remainder at {quarantine}: {exc}") from exc
    if path.exists() or quarantine.exists():
        raise MaintenanceError(f"Removal incomplete: inspect {path} and {quarantine}")
    return {"detail": "Exact approved path removed after quarantine validation"}


CLEANERS = {"ollama-model": remove_ollama, "docker-build-cache": prune_docker,
            "docker-unused-images": prune_docker, "path": purge_path}


def clean(rt, plan, approval, *, session_run=False, progress=None):
    if plan.get("session_binding") and not session_run:
        raise MaintenanceError("Session-bound plan: use session run with its persisted approval and rubric gates")
    validate_plan(plan, approval, rt.now)
    preflight(rt, plan)  # Every selection must pass before any deletion starts.
    receipt = {"schema": SCHEMA, "plan": plan["id"], "created": rt.now,
               "before_volumes": rt.volumes(), "results": []}
    expected_models = dict(plan["catalogs"].get("ollama", {}))
    for row in plan["items"]:
        action = row["action"]
        if progress:
            progress({"id": row["id"], "item": row["item"], "status": "executing"})
        try:
            result = CLEANERS[action["adapter"]](rt, action, plan["id"])
            if action["adapter"] == "ollama-model":
                expected_models.pop(action["model"])
                if model_catalog(rt, action["endpoint"]) != expected_models:
                    raise MaintenanceError("Ollama post-check differs from the selected removals; reconcile before continuing")
            receipt["results"].append({"id": row["id"], "item": row["item"], "status": "done", **result})
        except (MaintenanceError, OSError) as exc:
            receipt["results"].append({"id": row["id"], "item": row["item"], "status": "failed", "detail": str(exc)})
            if progress:
                progress(receipt["results"][-1])
            break
        if progress:
            progress(receipt["results"][-1])
    completed = {r["id"] for r in receipt["results"]}
    receipt["results"] += [{"id": r["id"], "item": r["item"], "status": "not_run", "detail": "Earlier action failed"}
                            for r in plan["items"] if r["id"] not in completed]
    if any(r["action"]["adapter"] == "ollama-model" for r in plan["items"]):
        try:
            current = model_catalog(rt, plan["ollama_endpoint"])
            if current != expected_models:
                raise MaintenanceError("Retained model names/digests differ; cleanup requires reconciliation")
            for name in current:
                rt.ollama(plan["ollama_endpoint"], "show", {"model": name})
            receipt["model_check"] = "Retained names/digests and metadata verified; inference was not run"
        except MaintenanceError as exc:
            receipt["model_check"] = str(exc)
            receipt["verification_failed"] = True
    receipt["after_volumes"] = rt.volumes()
    return receipt


def render_plan(plan):
    return f"Plan: `{plan['id']}` — pending owner approval\n\n" + table(
        ["ID", "Selected item", "Size", "Action"], [
            [r["id"], r["item"], gib(r["size"]), action_text(r["action"])] for r in plan["items"]])


def render_receipt(receipt):
    rows = [[r["id"], r["item"], r["status"], r["detail"]] for r in receipt["results"]]
    before = {v["path"]: v for v in receipt["before_volumes"]}
    volumes = []
    for volume in receipt["after_volumes"]:
        old = before.get(volume["path"], {}).get("free")
        new = volume.get("free")
        delta = "Unmeasured" if old is None or new is None else gib(new - old)
        volumes.append([volume["path"], gib(old), gib(new), delta])
    return (table(["ID", "Item", "Result", "Evidence"], rows) + "\n\n" +
            table(["Volume", "Free before", "Free now", "Observed change"], volumes) +
            ("\n\n" + receipt["model_check"] if "model_check" in receipt else ""))


def state_root(value=None):
    if value:
        return Path(value).expanduser().absolute()
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/System Maintenance"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "system-maintenance"


def save_document(state, category, identity, document):
    return save_text(state, category, identity, json.dumps(document, indent=2) + "\n", suffix=".json")


def save_text(state, category, identity, contents, suffix=".md"):
    folder = state / category
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = folder / (identity + suffix)
    fd, temporary = tempfile.mkstemp(prefix=".writing-", dir=folder)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(contents)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def load_document(state, category, identity):
    folder = state / category
    if identity == "last":
        choices = sorted(folder.glob("*.json"), key=lambda p: p.stat().st_mtime_ns)
        if not choices:
            raise MaintenanceError(f"No saved {category}; run the previous step first")
        path = choices[-1]
    else:
        if not re.fullmatch(r"(?:report|plan)-[a-z0-9-]+", identity):
            raise MaintenanceError("Use the saved report or plan ID")
        path = folder / (identity + ".json")
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise MaintenanceError(f"Cannot read saved {category}: {exc}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", help="Override the small report/plan/receipt directory")
    sub = parser.add_subparsers(dest="mode", required=True)
    audit_parser = sub.add_parser("audit", help="Inventory only; --save writes a report, never deletes")
    audit_parser.add_argument("--scope", default="system,docker,ollama", help="Comma-separated system,docker,ollama,external or all")
    audit_parser.add_argument("--path", action="append", default=[], help="Explicit ordinary path to inspect as a cleanup candidate")
    audit_parser.add_argument("--timeout", type=int, default=10, help="Per-directory measurement timeout, 1–60 seconds")
    audit_parser.add_argument("--save", action="store_true")
    audit_parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    report_parser = sub.add_parser("report", help="Show a saved report")
    report_parser.add_argument("--report", default="last")
    plan_parser = sub.add_parser("plan", help="Prepare selected actions; never deletes")
    plan_parser.add_argument("--report", required=True, help="Report ID whose rows the owner reviewed")
    plan_parser.add_argument("--select", nargs="+", required=True)
    clean_parser = sub.add_parser("clean", help="Execute the exact plan after owner approval")
    clean_parser.add_argument("--plan", required=True)
    clean_parser.add_argument("--approve", help="Exact plan ID approved by the owner")
    args = parser.parse_args(argv)
    rt, state = Runtime(), state_root(args.state_dir)
    try:
        if args.mode == "audit":
            scopes = set(args.scope.split(","))
            if scopes == {"all"}:
                scopes = {"system", "docker", "ollama", "external"}
            if not scopes <= {"system", "docker", "ollama", "external"} or not 1 <= args.timeout <= 60:
                raise MaintenanceError("Invalid scope or timeout")
            report = audit(rt, scopes, args.path, args.timeout)
            if args.save:
                report["id"] = "report-" + secrets.token_hex(8)
                save_document(state, "reports", report["id"], report)
            print(json.dumps(report, indent=2) if args.format == "json" else render_report(report))
            if args.save and args.format != "json":
                print(f"\nSaved report: `{report['id']}`")
        elif args.mode == "report":
            print(render_report(load_document(state, "reports", args.report)))
        elif args.mode == "plan":
            report = load_document(state, "reports", args.report)
            plan = prepare_plan(rt, report, args.select)
            save_document(state, "plans", plan["id"], plan)
            print(render_plan(plan))
        else:
            plan = load_document(state, "plans", args.plan)
            receipt = clean(rt, plan, args.approve)
            identity = plan["id"] + "-" + secrets.token_hex(4)
            path = save_document(state, "receipts", identity, receipt)
            print(render_receipt(receipt))
            print(f"\nReceipt: {path}")
            if receipt.get("verification_failed") or any(r["status"] != "done" for r in receipt["results"]):
                return 2
        return 0
    except (MaintenanceError, OSError, KeyError, ValueError) as exc:
        print(f"Blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
