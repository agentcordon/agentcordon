#!/usr/bin/env python3
"""Fail when a module under core's proxy or the server's middleware has no
non-test caller.

Both trees are enforcement code: a module nobody calls is a check that is
not being made (the URL matcher sat unused for a release while the UI
showed the pattern as if it were enforced). Run from the repo root; CI runs
it after clippy.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TREES = [
    ("crates/core/src/proxy", "proxy"),
    ("crates/server/src/middleware", "middleware"),
]
SKIP = {"mod.rs"}


def is_test_path(path: pathlib.Path) -> bool:
    parts = path.parts
    return "tests" in parts or path.name.endswith("_tests.rs") or path.name == "tests.rs"


def rust_sources():
    for path in (ROOT / "crates").rglob("*.rs"):
        if "target" in path.parts:
            continue
        yield path


def strip_test_modules(text: str) -> str:
    """Drop `#[cfg(test)] mod ... { ... }` blocks so in-file tests do not count."""
    out = []
    i = 0
    marker = "#[cfg(test)]"
    while True:
        j = text.find(marker, i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        brace = text.find("{", j)
        if brace < 0:
            break
        depth = 0
        k = brace
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        i = k + 1
    return "".join(out)


def main() -> int:
    sources = {p: strip_test_modules(p.read_text()) for p in rust_sources() if not is_test_path(p)}
    dead = []
    for tree, parent in TREES:
        for module_file in sorted((ROOT / tree).glob("*.rs")):
            if module_file.name in SKIP:
                continue
            module = module_file.stem
            # A caller names the module through its parent (`proxy::url_match`)
            # or through a re-export (`use ...::proxy::{url_match, ...}`).
            pattern = re.compile(rf"\b{parent}::(\{{[^}}]*\b{module}\b[^}}]*\}}|{module}\b)")
            callers = [p for p, text in sources.items() if p != module_file and pattern.search(text)]
            if not callers:
                dead.append(f"{tree}/{module_file.name}")
    if dead:
        print("modules with no non-test caller:")
        for d in dead:
            print(f"  {d}")
        return 1
    print("every enforcement module has a caller")
    return 0


if __name__ == "__main__":
    sys.exit(main())
