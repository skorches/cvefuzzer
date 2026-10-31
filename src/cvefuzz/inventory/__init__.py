"""Passive discovery: no repository code, scripts, or builds are executed."""

import hashlib
import os
from pathlib import Path

from ..adapters import REGISTRY, capabilities

DEFAULT_EXCLUDES = frozenset({".git", ".venv", "venv", "node_modules", "vendor", "__pycache__", ".cvefuzz", ".tools", "build", "dist"})


def discover(root: Path, excludes=()):
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository must be a directory")
    excluded = DEFAULT_EXCLUDES | set(excludes)
    files, manifests, unknown, errors, skipped = [], [], [], [], []
    languages = {}
    digest = hashlib.sha256()

    def walk_error(error):
        errors.append(str(error))

    for directory, dirs, names in os.walk(root, onerror=walk_error, followlinks=False):
        base = Path(directory)
        kept = []
        for name in sorted(dirs):
            path = base / name
            if name in excluded or path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                skipped.append(path.relative_to(root).as_posix())
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped.append(relative)
                continue
            try:
                file_hash = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        file_hash.update(block)
                content_hash = file_hash.hexdigest()
            except OSError as error:
                errors.append(f"{relative}: {error}")
                continue
            digest.update(relative.encode("utf-8") + b"\0" + content_hash.encode("ascii") + b"\0")
            detected = []
            for language, spec in REGISTRY.items():
                if path.suffix.lower() in spec["extensions"] or name in spec["manifests"]:
                    detected.append(language)
                    languages[language] = languages.get(language, 0) + 1
                if name in spec["manifests"]:
                    manifests.append({"path": relative, "language": language, "parsed": False})
            files.append({"path": relative, "sha256": content_hash, "languages": detected})
            if not detected:
                unknown.append(relative)
    return {"files": files, "languages": languages, "manifests": manifests,
            "unclassified_files": unknown, "errors": errors, "skipped_paths": skipped,
            "capabilities": capabilities(), "content_identity": "sha256:" + digest.hexdigest()}
