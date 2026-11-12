"""Passive provenance from npm v2/v3 package maps; never resolve or install."""

from collections import deque
import json


def dependency_paths(lockfile):
    """Return one deterministic shortest declared path per name/version, plus gaps."""
    data = json.loads(lockfile.read_text(encoding="utf-8-sig"))
    if data.get("lockfileVersion") not in (2, 3):
        raise ValueError("npm provenance supports lockfileVersion 2 and 3 only")
    packages = data.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise ValueError("npm provenance requires a packages map with a root entry")
    for location, package in packages.items():
        if not isinstance(package, dict):
            raise ValueError(f"Invalid npm package record: {location}")
        if "version" in package and not isinstance(package["version"], str):
            raise ValueError(f"Invalid npm package version: {location}")
        if "name" in package and not isinstance(package["name"], str):
            raise ValueError(f"Invalid npm package name: {location}")
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            entries = package.get(field, {})
            if not isinstance(entries, dict) or any(not isinstance(value, str) for value in entries.values()):
                raise ValueError(f"Invalid npm {field}: {location}")
    paths, issues, visited = {}, [], {""}
    queue = deque([("", [])])
    while queue:
        location, chain = queue.popleft()
        package = packages[location]
        if package.get("link"):
            issues.append(f"Linked npm package provenance unsupported: {location}")
            continue
        dependencies = {}
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            dependencies.update(package.get(field, {}))
        if not location:
            dependencies.update(package.get("devDependencies", {}))
        for name in sorted(dependencies):
            # Node searches the requester's node_modules, then ancestor directories.
            parent = location
            target = None
            while True:
                candidate = f"{parent}/node_modules/{name}" if parent else f"node_modules/{name}"
                if candidate in packages:
                    target = candidate
                    break
                if not parent:
                    break
                parent = parent.rpartition("/node_modules/")[0]
            if target is None:
                optional = name in package.get("optionalDependencies", {}) or package.get("peerDependenciesMeta", {}).get(name, {}).get("optional")
                if not optional:
                    issues.append(f"Unresolved npm dependency path: {location or '<root>'} -> {name}")
                continue
            entry = packages[target]
            version = entry.get("version")
            identity = entry.get("name", name)
            if dependencies[name].startswith("npm:"):
                issues.append(f"npm alias provenance unsupported: {name}")
                continue
            next_chain = chain + [f"{identity}@{version or '?'}"]
            if version and not entry.get("link"):
                paths.setdefault((identity, version), next_chain)
            if target not in visited:
                visited.add(target)
                queue.append((target, next_chain))
    return paths, sorted(set(issues))
