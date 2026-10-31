"""Declared capabilities describe implemented features, not future support."""

REGISTRY = {
    "python": {"extensions": [".py"], "manifests": ["pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock", "uv.lock"]},
    "javascript": {"extensions": [".js", ".jsx", ".mjs", ".cjs"], "manifests": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]},
    "typescript": {"extensions": [".ts", ".tsx"], "manifests": ["tsconfig.json"]},
    "c": {"extensions": [".c", ".h"], "manifests": []},
    "cpp": {"extensions": [".cpp", ".cc", ".cxx", ".hpp"], "manifests": []},
    "go": {"extensions": [".go"], "manifests": ["go.mod", "go.sum"]},
    "java": {"extensions": [".java"], "manifests": ["pom.xml", "build.gradle", "build.gradle.kts"]},
    "rust": {"extensions": [".rs"], "manifests": ["Cargo.toml", "Cargo.lock"]},
}


def capabilities():
    return {
        language: {"inventory": True, "dependency_scan": False,
                   "static_analysis": False, "reachability": False,
                   "build": False, "fuzzing": False}
        for language in REGISTRY
    }
