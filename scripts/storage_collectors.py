"""Read-only native collectors. No agent-authored observations or cleanup calls."""
from __future__ import annotations

from collections import Counter, defaultdict
import copy
import json
import os
from pathlib import Path
import stat
import time

import storage

COLLECTOR_VERSION = 1
SECTIONS = ("caches", "docker-images", "docker-containers", "docker-volumes", "models", "external")
# These are ownership/recovery contracts, not inferred cleanup permissions.
# Only the two ordinary filesystem caches have an existing guarded path adapter.
CACHE_RULES = {
    "Library/Caches/electron": ("Electron archive downloads", "cache", "redownload", True),
    "Library/Caches/node-gyp": ("Node native-build headers", "cache", "redownload", True),
    "Library/Caches/FluidAudio": ("FluidAudio compiled speech models", "installed_model", "unknown", False),
    "Library/Caches/codex": ("Active Codex application cache", "unknown", "unknown", False),
    "Library/Caches/ms-playwright": ("Playwright browser binaries", "cache", "redownload", False),
    "Library/Caches/ms-playwright-go": ("Playwright Go driver binaries", "cache", "redownload", False),
    "Library/Caches/ms-playwright-mcp": ("Playwright saved automation profiles", "unknown", "unknown", False),
    "Library/Caches/camoufox": ("Camoufox browser binaries", "cache", "redownload", False),
    "Library/Caches/org.swift.swiftpm": ("Swift Package Manager", "cache", "redownload", False),
    ".cache/uv": ("UV package cache", "cache", "redownload", False),
    ".cache/puppeteer": ("Puppeteer browser binaries", "cache", "redownload", False),
    ".cache/huggingface": ("Hugging Face models and download cache", "installed_model", "unknown", False),
    ".cache/codex-runtimes": ("Codex runtime binaries", "unknown", "unknown", False),
}
DATABASE_MARKERS = {"PG_VERSION", "WiredTiger", "ibdata1", "dump.rdb", "appendonly.aof", "db.sqlite3", "database.db"}
MODEL_SUFFIXES = {".gguf", ".safetensors", ".mlmodelc", ".mlpackage"}
OS_VOLUME_METADATA = {".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems", ".DocumentRevisions-V100"}


def empty_report(rt):
    return {"schema": storage.SCHEMA, "created": rt.now, "measurements": [], "candidates": [], "volumes": [], "catalogs": {}, "checks": [], "notes": []}


def survey(path, limit=512, seconds=3):
    """Metadata-only bounded traversal. A partial traversal cannot prove absence."""
    root = Path(path)
    result = {"entries": 0, "files": 0, "symlinks": 0, "complete": True, "database_markers": [], "log_files": 0, "model_files": 0, "extensions": {}, "errors": []}
    stack, extensions = [root], Counter()
    deadline = time.monotonic() + seconds
    while stack:
        if result["entries"] >= limit or time.monotonic() > deadline:
            result["complete"] = False
            break
        node = stack.pop()
        try:
            st = node.lstat()
            result["entries"] += 1
            if stat.S_ISLNK(st.st_mode):
                result["symlinks"] += 1
                continue
            if node.name in DATABASE_MARKERS or node.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
                result["database_markers"].append(node.name)
            if node.suffix.lower() in MODEL_SUFFIXES:
                result["model_files"] += 1
            if stat.S_ISDIR(st.st_mode):
                with os.scandir(node) as entries:
                    children = []
                    for entry in entries:
                        children.append(Path(entry.path))
                        if len(children) > limit:
                            result["complete"] = False
                            break
                stack.extend(sorted(children, reverse=True))
            elif stat.S_ISREG(st.st_mode):
                result["files"] += 1
                extensions[node.suffix.lower() or "[none]"] += 1
                if node.suffix.lower() == ".log":
                    result["log_files"] += 1
        except OSError as exc:
            result["complete"] = False
            result["errors"].append(type(exc).__name__)
    result["extensions"] = dict(sorted(extensions.items()))
    result["database_markers"] = sorted(set(result["database_markers"]))
    return result


def first_level_usage(rt, root, timeout):
    raw = rt.command(["du", "-k", "-x", "-d", "1", str(root)], timeout=timeout)
    rows = []
    for line in raw.splitlines():
        number, value = line.split("\t", 1)
        path = Path(value)
        if path.parent == root:
            size = int(number) * 1024
            if size < 0:
                raise storage.MaintenanceError("Negative native usage result")
            rows.append((path, size))
    return sorted(rows, key=lambda x: (-x[1], str(x[0])))


def row(selector, title, category, location, size, facts, observations, action=None, protected_reason=None):
    candidate = {"id": storage.candidate_id(category, selector), "item": title, "category": category, "location": location,
                 "size": size, "reclaimable": None, "status": "review", "reason": "Automatically collected native evidence; not cleanup approval"}
    if action:
        candidate["action"] = action
    if protected_reason:
        candidate["collector_protected"] = protected_reason
    return {"candidate": candidate, "facts": facts, "machine_observations": observations}


class Collector:
    def __init__(self, rt, max_resources=64, timeout=10, entry_limit=512):
        self.rt, self.max_resources, self.timeout, self.entry_limit = rt, max_resources, timeout, entry_limit
        self._docker = None
        self._docker_error = None
        self._activity = None

    def activity(self, path):
        if self._activity is None:
            try:
                text = self.rt.command(["lsof", "-nP", "-Fn"], timeout=self.timeout)
                self._activity = [x[1:] for x in text.splitlines() if x.startswith("n/")]
            except storage.MaintenanceError:
                self._activity = False
        if self._activity is False:
            return "unknown", None
        prefix = str(path.resolve())
        def canonical(value):
            resolved = str(Path(value).resolve())
            apfs = "/System/Volumes/Data/"
            return "/" + resolved[len(apfs):] if resolved.startswith(apfs) else resolved
        prefix = canonical(prefix)
        count = 0
        for value in self._activity:
            if value == prefix or value.startswith(prefix + "/"):
                count += 1
            elif "/" + path.name + "/" in value or value.endswith("/" + path.name):
                # lsof and the discovery root can use /var vs /private/var,
                # APFS aliases or symlink spellings. Resolve plausible matches.
                resolved = canonical(value)
                if resolved == prefix or resolved.startswith(prefix + "/"):
                    count += 1
        return ("active" if count else "inactive"), count

    def path_row(self, path, size, section, level=0):
        details = survey(path, self.entry_limit if level == 0 else self.entry_limit * 8)
        try:
            relative = str(path.relative_to(self.rt.home))
        except ValueError:
            relative = "external/" + path.name
        rule = CACHE_RULES.get(relative)
        owner, content, recovery, path_adapter = rule or ("", "unknown", "unknown", False)
        native_cleanup_available = relative == "Library/Caches/node-gyp" and bool(storage.shutil.which("node-gyp"))
        if native_cleanup_available:
            # Prefer its native version-scoped remove operation. This session
            # has no such adapter yet, so report that gap instead of raw deletion.
            path_adapter = False
        activity, opened = self.activity(path)
        if details["database_markers"]:
            content = "database"
        elif details["model_files"]:
            content = "installed_model"
        elif details["log_files"]:
            content = "logs"
        elif details["complete"] and details["files"] == 0 and details["symlinks"] == 0:
            content = "empty"
        if content == "cache" and relative == "Library/Caches/electron" and any(ext not in {".zip", ".sha256", ".sha512"} for ext in details["extensions"]):
            content = "unknown"
        if not details["complete"] and content not in {"database", "installed_model", "logs"}:
            content = "unknown"
        action = None
        gate = None
        if path_adapter and content in {"cache", "empty"} and activity == "inactive" and details["complete"]:
            try:
                expected = storage.path_snapshot(self.rt, path)
                self.rt.no_open_files(path)
                action = {"adapter": "path", "path": expected["path"], "expected": expected}
            except (storage.MaintenanceError, OSError) as exc:
                gate = str(exc)
        facts = {"owner": owner, "content_class": content, "activity": activity, "recovery": recovery,
                 "notes": "Collector observations and registry ownership contract; no file contents were read", "evidence_refs": []}
        observations = {"collector": "filesystem-metadata-v1", "resource": relative, "measured_bytes": size,
                        "ownership_rule": owner or None, "recovery_contract": recovery, "open_file_count": opened,
                        "survey": details, "native_cleanup_available": native_cleanup_available, "native_preflight_failure": gate, "probe_level": level}
        reason = "Resource has open files; interruption requires separate owner approval" if activity == "active" else None
        if relative in {"Library/Caches/codex", ".cache/codex-runtimes"}:
            reason = "Active application/runtime cache is preserved"
        return row(str(path), relative, section, str(path), size, facts, observations, action, reason)

    def paths(self, section):
        roots = [self.rt.home / "Library/Caches", self.rt.home / ".cache"] if section == "caches" else [Path(v["path"]) for v in self.rt.volumes() if v.get("external")]
        rows, measurements, notices = [], [], []
        for root in roots:
            if not root.exists():
                notices.append({"kind": "missing_root", "detail": str(root) + " is absent; no contents measured"})
                continue
            if root.is_symlink():
                target = root.resolve()
                measurements.append({"path": str(root), "resolved": str(target), "bytes": None, "status": "Linked root; inspect resolved target without deleting the link"})
                root = target
            try:
                if section == "external":
                    # Whole-volume du can fail on OS metadata and discard all
                    # readable results. Reuse the canonical bounded path probe.
                    children = sorted(root.iterdir(), key=lambda p: p.name)
                    usage, candidates = [], []
                    deadline = time.monotonic() + self.timeout * 2
                    for path in children:
                        if path.name in OS_VOLUME_METADATA:
                            measurements.append({"path": str(path), "bytes": None, "status": "Protected OS volume metadata; not inspected"})
                        else:
                            candidates.append(path)
                    if len(candidates) > self.max_resources:
                        notices.append({"kind": "collection_limit", "detail": f"{root}: {len(candidates)} children exist; only {self.max_resources} fit this inspection budget. Remaining contents are unclassified."})
                    for path in candidates[:self.max_resources]:
                        if time.monotonic() >= deadline:
                            measurements.append({"path": str(path), "bytes": None, "status": "not_run: per-drive inspection budget reached"})
                            notices.append({"kind": "collection_time_limit", "detail": f"{path}: not measured within per-drive budget; not zero usage"})
                            continue
                        measured = storage.measured_path(self.rt, path, self.timeout)
                        measurements.append(measured)
                        usage.append((path, measured["bytes"]))
                        if measured["bytes"] is None:
                            notices.append({"kind": "collector_failure", "detail": f"{path}: {measured.get('detail', measured['status'])}; usage remains unmeasured"})
                    usage.sort(key=lambda pair: (-(pair[1] or 0), str(pair[0])))
                else:
                    usage = first_level_usage(self.rt, root, self.timeout)
            except (storage.MaintenanceError, OSError, ValueError) as exc:
                diagnostic = str(exc) if isinstance(exc, (storage.MaintenanceError, OSError)) else type(exc).__name__
                notices.append({"kind": "collector_failure", "detail": f"{root}: {diagnostic}; usage is unmeasured"})
                continue
            if section != "external":
                measurements.extend({"path": str(p), "bytes": size, "status": "native first-level measurement"} for p, size in usage)
            if section == "caches":
                system = [(p, size) for p, size in usage if p.name.startswith("com.apple.") or p.name in {"CloudKit", "GeoServices"}]
                usage = [(p, size) for p, size in usage if (p, size) not in system]
                if system:
                    rows.append(row(str(root) + "/[OS-managed]", "OS-managed caches", section, str(root), sum(size for _, size in system),
                                    {"owner": "macOS", "content_class": "unknown", "activity": "unknown", "recovery": "unknown", "evidence_refs": []},
                                    {"collector": "filesystem-metadata-v1", "directory_count": len(system), "policy": "Retain OS-managed caches"}, protected_reason="OS-managed caches are outside automatic retirement scope"))
            if len(usage) > self.max_resources:
                notices.append({"kind": "collection_limit", "detail": f"{root}: measured {len(usage)} children; inspected largest {self.max_resources}. Remaining {len(usage)-self.max_resources} need review, not assumed disposable."})
            for path, size in usage[:self.max_resources]:
                rows.append(self.path_row(path, size, section))
        return rows, measurements, notices

    def docker(self):
        if self._docker_error is not None:
            raise storage.MaintenanceError("Shared native Docker inventory unavailable; earlier collector failure retained")
        if self._docker is None:
            try:
                context = storage.docker_context(self.rt)
                socket = context["endpoint"][7:]
                def get(path):
                    return json.loads(self.rt.command(["curl", "--fail", "--silent", "--show-error", "--noproxy", "*", "--unix-socket", socket, "http://localhost" + path], timeout=self.timeout))
                df, containers = get("/system/df"), get("/containers/json?all=1&size=1")
                if not isinstance(df, dict) or not isinstance(containers, list) or any(k not in df or (df[k] is not None and not isinstance(df[k], list)) for k in ("Images", "Volumes")):
                    raise storage.MaintenanceError("Native Docker inventory schema is incomplete; not an empty inventory")
                if any(not isinstance(c, dict) or not all(isinstance(c.get(k), str) and c[k] for k in ("Id", "ImageID", "State")) or (c.get("Mounts") is not None and not isinstance(c["Mounts"], list)) for c in containers):
                    raise storage.MaintenanceError("Native container reference/state evidence is incomplete")
                self._docker = context, df, containers
            except (storage.MaintenanceError, OSError, ValueError) as exc:
                self._docker_error = type(exc).__name__
                raise
        return self._docker

    def docker_rows(self, section):
        context, df, containers = self.docker()
        references = defaultdict(list)
        for c in containers:
            references[c["ImageID"]].append({"id": c["Id"], "state": c.get("State", "unknown")})
        rows = []
        if section == "docker-images":
            for image in df.get("Images") or []:
                tags = sorted(image.get("RepoTags") or image.get("RepoDigests") or [])
                refs = references[image["Id"]]
                recover = "redownload" if image.get("RepoDigests") else "unknown"
                r = row(image["Id"], ", ".join(tags) or image["Id"][:19], section, context["name"], image.get("Size"),
                        {"owner": "Docker image registry" if recover == "redownload" else "Local Docker image; origin unresolved", "content_class": "cache", "activity": "active" if refs else "inactive", "recovery": recover, "evidence_refs": []},
                        {"collector": "docker-api-v1", "image_id": image["Id"], "tags": tags, "container_references": refs, "shared_bytes": image.get("SharedSize"), "unique_bytes": image.get("Size", 0) - max(0, image.get("SharedSize", 0))},
                        protected_reason="Image referenced by an existing container" if refs else None)
                r["candidate"]["selectors"] = [image["Id"], *(image.get("RepoTags") or []), *(image.get("RepoDigests") or [])]
                rows.append(r)
            native = storage.docker_rows(self.rt, context)
            build = native.get("Build Cache")
            if build is None:
                raise storage.MaintenanceError("Native Docker build-cache usage is missing")
            reclaimable = storage.parse_size(build.get("Reclaimable"))
            if reclaimable is None:
                raise storage.MaintenanceError("Native Docker build-cache recovery is unmeasured")
            if reclaimable > 0:
                r = row(context, "Unused Docker build cache", section, context["name"], storage.parse_size(build.get("Size")),
                        {"owner": "Docker BuildKit", "content_class": "cache", "activity": "inactive", "recovery": "rebuild", "evidence_refs": []},
                        {"collector": "docker-native-df-v1", "native_row": build, "scope": "Only unused build cache; no images, containers or volumes"},
                        {"adapter": "docker-build-cache", "context": context, "kind": "Build Cache", "expected": storage.digest(build)})
                r["candidate"]["reclaimable"] = reclaimable
                rows.append(r)
        elif section == "docker-containers":
            groups = defaultdict(list)
            for c in containers:
                if c.get("State") not in {"exited", "created", "dead"}:
                    continue
                labels = c.get("Labels") or {}
                groups[labels.get("com.docker.compose.project", "unlabelled")].append(c)
            for project, members in sorted(groups.items()):
                observed = [{"id": c["Id"], "names": c.get("Names", []), "image": c.get("Image"), "state": c.get("State"), "writable_bytes": c.get("SizeRw"),
                             "mounts": [{"type": m.get("Type"), "name": m.get("Name"), "destination": m.get("Destination")} for m in c.get("Mounts") or []]} for c in members]
                sizes = [c.get("SizeRw") for c in members]
                rows.append(row(project, project + " stopped containers", section, context["name"], sum(sizes) if all(isinstance(x, int) and x >= 0 for x in sizes) else None,
                                {"owner": project, "content_class": "unknown", "activity": "inactive", "recovery": "unknown", "evidence_refs": []},
                                {"collector": "docker-api-v1", "containers": observed, "intentional_retention_not_established": True, "count": len(members)}))
        else:
            volume_refs = defaultdict(list)
            for c in containers:
                for mount in c.get("Mounts") or []:
                    if mount.get("Type") == "volume" and mount.get("Name"):
                        volume_refs[mount["Name"]].append(c["Id"])
            for v in df.get("Volumes") or []:
                usage = v.get("UsageData") or {}
                refs = volume_refs[v["Name"]]
                if refs or usage.get("RefCount", -1) > 0:
                    continue
                labels = v.get("Labels") or {}
                size = usage.get("Size")
                size = size if isinstance(size, int) and size >= 0 else None
                rows.append(row(v["Name"], v["Name"], section, context["name"], size,
                                {"owner": labels.get("com.docker.compose.project", ""), "content_class": "unknown", "activity": "inactive" if usage.get("RefCount") == 0 else "unknown", "recovery": "unknown", "evidence_refs": []},
                                {"collector": "docker-api-v1", "references": refs, "native_reference_count": usage.get("RefCount"), "native_size_bytes": size,
                                 "compose_volume_role": labels.get("com.docker.compose.volume"), "contents_inspected": False, "safety": "Unreferenced is not disposable; no database or log contents were mounted or started"}))
        notices = []
        if len(rows) > self.max_resources:
            notices.append({"kind": "collection_limit", "detail": f"{section}: {len(rows)} resources observed; only {self.max_resources} sent to the bounded rubric. Remainder unclassified."})
        return rows[:self.max_resources], [], notices

    def models(self):
        report = empty_report(self.rt)
        storage.collect_ollama(self.rt, report)
        rows = [dict(candidate=c, facts={"owner": "Ollama", "content_class": "installed_model", "activity": "active" if c["status"] == "blocked" else "inactive", "recovery": "unknown", "evidence_refs": []},
                     machine_observations={"collector": "ollama-native-v1", "registered_name": c["item"], "digest": c["action"]["expected"], "reported_bytes": c["size"], "loaded": c["status"] == "blocked", "shared_size_warning": True}) for c in report["candidates"]]
        return rows[:self.max_resources], [], ([{"kind": "collection_limit", "detail": "Model catalog exceeds rubric resource bound; remaining registered models retained and unclassified"}] if len(rows) > self.max_resources else [])

    def collect(self, section):
        try:
            if section in {"caches", "external"}:
                rows, measurements, notices = self.paths(section)
            elif section.startswith("docker-"):
                rows, measurements, notices = self.docker_rows(section)
            elif section == "models":
                rows, measurements, notices = self.models()
            else:
                raise storage.MaintenanceError("Unsupported collector section")
        except (storage.MaintenanceError, OSError, ValueError, KeyError, TypeError) as exc:
            diagnostic = str(exc) if isinstance(exc, (storage.MaintenanceError, OSError)) else type(exc).__name__
            rows, measurements, notices = [], [], [{"kind": "collector_failure", "detail": f"{section}: {diagnostic}; native evidence unavailable, not zero"}]
        if len(rows) > self.max_resources:
            notices.append({"kind": "collection_limit", "detail": f"{section}: combined sources exceed {self.max_resources} candidates; remainder is measured where possible but not classified"})
            rows = sorted(rows, key=lambda r: (-(r["candidate"].get("size") or 0), r["candidate"]["id"]))[:self.max_resources]
        report = empty_report(self.rt)
        report["candidates"] = [r["candidate"] for r in rows]
        report["measurements"] = measurements
        report["notes"] = ["Read-only automatic collection; database/log/installed-model preservation and approval remain mandatory"]
        return {"collector_version": COLLECTOR_VERSION, "section": section, "report": report, "rows": rows, "notices": notices}

    def expand(self, bundle, ids):
        """One metadata-only content probe; never invent an owning command."""
        expanded = copy.deepcopy(bundle)
        changed = False
        for index, previous in enumerate(bundle["rows"]):
            candidate = previous["candidate"]
            details = previous["machine_observations"]
            if candidate["id"] in ids and details.get("collector") == "filesystem-metadata-v1" and details.get("survey", {}).get("complete") is False and details.get("probe_level") == 0:
                fresh = self.path_row(Path(candidate["location"]), candidate["size"], bundle["section"], level=1)
                if fresh["machine_observations"] != details:
                    expanded["rows"][index] = fresh
                    changed = True
        if changed:
            expanded["report"]["candidates"] = [r["candidate"] for r in expanded["rows"]]
        return expanded if changed else None
