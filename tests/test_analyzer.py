"""核心分析逻辑的轻量自测（无测试框架依赖）：python -m tests.test_analyzer"""

from __future__ import annotations

from app import analyzer, licenses


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def test_normalization() -> None:
    cases = {
        "MIT": ("MIT", True),
        "mit license": ("MIT", True),
        "Apache 2.0": ("Apache-2.0", True),
        "gplv3": ("GPL-3.0", True),
        "lgplv2": ("LGPL-2.1", True),
        "BSD3": ("BSD-3-Clause", True),
        "CC0": ("CC0-1.0", True),
        "GPL-3.0-or-later": ("GPL-3.0", True),
        "commercial": ("Proprietary", True),
        "OFL-1.1": ("ofl-1.1", False),
    }
    for raw, (token, known) in cases.items():
        _, got_token, got_known = licenses.normalize_license(raw)
        _check("normalize %r" % raw, got_token == token and got_known == known)


def test_matrix_rules() -> None:
    expectations = [
        ("MIT", "GPL-3.0", licenses.OK),
        ("GPL-2.0", "Apache-2.0", licenses.CONFLICT),
        ("GPL-3.0", "Proprietary", licenses.CONFLICT),
        ("Proprietary", "MIT", licenses.OK),
        ("Proprietary", "LGPL-3.0", licenses.WARNING),
        ("Proprietary", "GPL-2.0", licenses.CONFLICT),
        ("MPL-2.0", "GPL-2.0", licenses.CONFLICT),
        ("MPL-2.0", "GPL-3.0", licenses.OK),
        ("AGPL-3.0", "Proprietary", licenses.CONFLICT),
        ("MIT", "Proprietary", licenses.WARNING),
        ("MIT", "weird-license", licenses.WARNING),
    ]
    for parent, dep, want in expectations:
        got, reason = licenses.compatibility(parent, dep)
        _check("compat %s->%s == %s (%s)" % (parent, dep, got, reason), got == want)


def test_transitive_and_shortest_path() -> None:
    manifest = {
        "name": "t",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-3.0",
             "dependencies": ["mid@1"]},
            {"name": "mid", "version": "1", "license": "MIT",
             "dependencies": ["leaf@1"]},
            {"name": "leaf", "version": "1", "license": "Proprietary"},
        ],
        "edges": [{"source": "app@1", "target": "leaf@1"}],
    }
    result = analyzer.analyze_manifest(manifest)
    direct = [
        c for c in result["conflicts"]
        if c["ancestor"] == "app@1" and c["node"] == "leaf@1"
    ]
    _check("one app->leaf conflict", len(direct) == 1)
    _check(
        "shortest path uses direct edge",
        direct[0]["distance"] == 1 and direct[0]["path"] == ["app@1", "leaf@1"],
        str(direct[0]["path"]),
    )
    leaf = next(n for n in result["nodes"] if n["id"] == "leaf@1")
    sources = {c["from"] for c in leaf["constraints"]}
    _check("leaf constrained by app", "app@1" in sources, str(sources))


def test_cycle_safe() -> None:
    manifest = {
        "packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["a@1"]},
        ]
    }
    result = analyzer.analyze_manifest(manifest)
    _check("cycle does not crash", result["status"] == "clean")
    _check("cycle keeps 2 edges", result["summary"]["edges"] == 2)


def test_unresolved_and_filter() -> None:
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["ghost", "lib"]},
            {"name": "lib", "version": "1", "license": "MIT"},
            {"name": "lib", "version": "2", "license": "GPL-3.0"},
        ]
    }
    result = analyzer.analyze_manifest(manifest)
    refs = {u["reference"] for u in result["unresolved"]}
    _check("unknown + ambiguous refs unresolved", refs == {"ghost", "lib"}, str(refs))
    filtered = analyzer.filter_result(result, "lib")
    _check("filter keeps only lib nodes", {n["id"] for n in filtered["nodes"]} == {"lib@1", "lib@2"})


def main() -> None:
    test_normalization()
    test_matrix_rules()
    test_transitive_and_shortest_path()
    test_cycle_safe()
    test_unresolved_and_filter()
    print("\nall tests passed.")


if __name__ == "__main__":
    main()
