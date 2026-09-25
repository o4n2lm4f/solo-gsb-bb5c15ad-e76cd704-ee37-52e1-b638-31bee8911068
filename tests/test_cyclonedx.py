"""CycloneDX BOM 导入的轻量自测（无测试框架依赖）：python -m tests.test_cyclonedx

与 test_reviews 一样使用独立临时 SQLite 库验证历史列表/导出路径，
只依赖 analyzer/cyclonedx/database/compare，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from app import analyzer, compare as compare_mod, cyclonedx, database, licenses

# 隔离的临时数据库（database.connect 在调用时读取 DB_PATH，运行时替换即可）
_TMP_DIR = tempfile.mkdtemp(prefix="cyclonedx-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _bom(components, dependencies=None, **extra):
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}
    if dependencies is not None:
        bom["dependencies"] = dependencies
    bom.update(extra)
    return bom


def _comp(ref, name, version, licenses=None):
    comp = {"type": "library", "bom-ref": ref, "name": name, "version": version}
    if licenses is not None:
        comp["licenses"] = licenses
    return comp


def _demo_bom():
    """GPL-2.0 应用 -> Apache-2.0 库（硬冲突）-> MIT 库。"""
    return _bom(
        [
            _comp("ref-app", "app", "1.0.0", [{"license": {"id": "GPL-2.0"}}]),
            _comp("ref-lib", "lib", "2.0.0", [{"expression": "Apache-2.0"}]),
            _comp("ref-leaf", "leaf", "3.0.0", [{"license": {"id": "MIT"}}]),
        ],
        [
            {"ref": "ref-app", "dependsOn": ["ref-lib"]},
            {"ref": "ref-lib", "dependsOn": ["ref-leaf"]},
        ],
    )


def test_detection() -> None:
    _check("bomFormat triggers cyclonedx", cyclonedx.is_cyclonedx({"bomFormat": "CycloneDX"}))
    _check("components-only triggers cyclonedx", cyclonedx.is_cyclonedx({"components": []}))
    _check(
        "packages wins over components",
        not cyclonedx.is_cyclonedx({"packages": [], "components": []}),
    )
    _check("legacy manifest not cyclonedx", not cyclonedx.is_cyclonedx({"packages": []}))
    _check("non-dict not cyclonedx", not cyclonedx.is_cyclonedx([1, 2, 3]))
    legacy = analyzer.analyze_manifest(
        {"packages": [{"name": "a", "version": "1", "license": "MIT"}]}
    )
    _check("legacy manifest still analyzed", legacy["summary"]["packages"] == 1)


def test_basic_import_and_conflicts() -> None:
    result = analyzer.analyze_manifest(_demo_bom())
    _check("status conflict", result["status"] == "conflict", result["status"])
    _check("source_format marked", result.get("source_format") == "cyclonedx")
    _check("3 nodes", result["summary"]["packages"] == 3, str(result["summary"]))
    _check("2 edges", result["summary"]["edges"] == 2)
    edge_from = {e["from"] for e in result["edges"]}
    _check("edges tagged cyclonedx", edge_from == {cyclonedx.EDGE_SOURCE}, str(edge_from))
    conflict = next(
        c for c in result["conflicts"] if c["ancestor"] == "app@1.0.0" and c["node"] == "lib@2.0.0"
    )
    _check("GPL-2.0 vs Apache-2.0 hard conflict", conflict["severity"] == "error")
    _check(
        "shortest path direct",
        conflict["path"] == ["app@1.0.0", "lib@2.0.0"] and conflict["distance"] == 1,
        str(conflict["path"]),
    )
    leaf = next(n for n in result["nodes"] if n["id"] == "leaf@3.0.0")
    _check(
        "transitive constraint reaches leaf",
        any(c["from"] == "app@1.0.0" for c in leaf["constraints"]),
        str(leaf["constraints"]),
    )


def test_bom_ref_mapping() -> None:
    result = analyzer.analyze_manifest(_demo_bom())
    by_id = {n["id"]: n for n in result["nodes"]}
    _check(
        "bom-ref recorded on nodes",
        by_id["app@1.0.0"]["bom_refs"] == ["ref-app"]
        and by_id["lib@2.0.0"]["bom_refs"] == ["ref-lib"],
        str({k: v["bom_refs"] for k, v in by_id.items()}),
    )
    edges = {(e["source"], e["target"]) for e in result["edges"]}
    _check(
        "ref/dependsOn restored as node edges",
        ("app@1.0.0", "lib@2.0.0") in edges and ("lib@2.0.0", "leaf@3.0.0") in edges,
        str(edges),
    )


def test_license_sources() -> None:
    bom = _bom(
        [
            _comp("r1", "by-id", "1", [{"license": {"id": "Apache-2.0"}}]),
            _comp("r2", "by-expression", "1", [{"expression": "GPL-3.0"}]),
            _comp("r3", "by-name", "1", [{"license": {"name": "Apache 2.0"}}]),
            _comp("r4", "missing", "1"),
            _comp("r5", "or-expression", "1", [{"expression": "MIT OR Apache-2.0"}]),
            _comp("r6", "and-expression", "1", [{"expression": "MIT AND GPL-3.0"}]),
            _comp("r7", "paren-expression", "1", [{"expression": "(MIT OR Apache-2.0)"}]),
            _comp("r8", "unknown-or", "1", [{"expression": "MIT OR OFL-1.1"}]),
            _comp(
                "r9",
                "parallel-entries",
                "1",
                [{"license": {"id": "MIT"}}, {"license": {"id": "Apache-2.0"}}],
            ),
        ]
    )
    result = analyzer.analyze_manifest(bom)
    by_id = {n["id"]: n for n in result["nodes"]}
    _check("spdx id used", by_id["by-id@1"]["license"] == "Apache-2.0")
    _check("expression used", by_id["by-expression@1"]["license"] == "GPL-3.0")
    _check(
        "license.name fallback normalized",
        by_id["by-name@1"]["license"] == "Apache-2.0" and by_id["by-name@1"]["license_known"],
    )
    _check(
        "missing license unknown",
        by_id["missing@1"]["license_known"] is False
        and by_id["missing@1"]["license_display"] == "UNLICENSED",
        str(by_id["missing@1"]),
    )
    # 纯 OR 表达式：矩阵内标识 -> 多候选
    or_node = by_id["or-expression@1"]
    _check(
        "pure OR expression parsed as candidates",
        or_node["license_multi"] is True
        and or_node["license_tokens"] == ["MIT", "Apache-2.0"]
        and or_node["license_category"] == licenses.MULTI,
        str(or_node),
    )
    # AND / 括号 / 含未知标识的 OR：仍按未知处理
    for key, display in (
        ("and-expression@1", "MIT AND GPL-3.0"),
        ("paren-expression@1", "(MIT OR Apache-2.0)"),
        ("unknown-or@1", "MIT OR OFL-1.1"),
    ):
        _check(
            "%s stays unknown" % display,
            by_id[key]["license_known"] is False and by_id[key]["license_multi"] is False,
            str(by_id[key]),
        )
    # 多个并列许可证条目：同样按候选处理
    parallel = by_id["parallel-entries@1"]
    _check(
        "parallel license entries become candidates",
        parallel["license_multi"] is True
        and parallel["license_tokens"] == ["MIT", "Apache-2.0"],
        str(parallel),
    )


def test_same_component_merges_when_license_agrees() -> None:
    bom = _bom(
        [
            _comp("ref-a", "lib", "1.0.0", [{"license": {"id": "MIT"}}]),
            _comp("ref-b", "lib", "1.0.0", [{"license": {"name": "MIT License"}}]),
            _comp("ref-app", "app", "1", [{"license": {"id": "MIT"}}]),
        ],
        [
            {"ref": "ref-app", "dependsOn": ["ref-a"]},
            {"ref": "ref-a", "dependsOn": ["ref-b"]},
        ],
    )
    result = analyzer.analyze_manifest(bom)
    _check("same name+version+license merged", result["summary"]["packages"] == 2, str(result["summary"]))
    lib = next(n for n in result["nodes"] if n["id"] == "lib@1.0.0")
    _check("both bom-refs mapped to merged node", lib["bom_refs"] == ["ref-a", "ref-b"], str(lib["bom_refs"]))
    _check("no self edge after merge", result["summary"]["edges"] == 1, str(result["edges"]))


def test_duplicate_bom_ref_rejected() -> None:
    bom = _bom(
        [
            _comp("dup-ref", "lib-a", "1.0.0", [{"license": {"id": "MIT"}}]),
            _comp("dup-ref", "lib-b", "2.0.0", [{"license": {"id": "MIT"}}]),
        ]
    )
    result = analyzer.analyze_manifest(bom)
    _check("duplicate bom-ref -> error", result["status"] == "error")
    _check(
        "error mentions bom-ref",
        "bom-ref" in result["error"] and "dup-ref" in result["error"],
        result["error"],
    )


def test_conflicting_license_rejected() -> None:
    bom = _bom(
        [
            _comp("ref-a", "lib", "1.0.0", [{"license": {"id": "MIT"}}]),
            _comp("ref-b", "lib", "1.0.0", [{"license": {"id": "GPL-3.0"}}]),
        ]
    )
    result = analyzer.analyze_manifest(bom)
    _check("same name+version different license -> error", result["status"] == "error")
    _check(
        "error mentions both licenses",
        "lib@1.0.0" in result["error"] and "MIT" in result["error"] and "GPL-3.0" in result["error"],
        result["error"],
    )


def test_unresolved_refs_kept_as_warnings() -> None:
    bom = _bom(
        [
            _comp("ref-app", "app", "1", [{"license": {"id": "MIT"}}]),
            _comp("ref-lib", "lib", "1", [{"license": {"id": "MIT"}}]),
        ],
        [
            {"ref": "ref-app", "dependsOn": ["ref-lib", "ref-ghost"]},
            {"ref": "ref-missing-source", "dependsOn": ["ref-lib"]},
        ],
    )
    result = analyzer.analyze_manifest(bom)
    _check("valid edge still restored", result["summary"]["edges"] == 1, str(result["edges"]))
    _check("two unresolved entries", result["summary"]["unresolved"] == 2, str(result["unresolved"]))
    by_ref = {u["reference"]: u for u in result["unresolved"]}
    _check(
        "missing dependsOn target recorded",
        by_ref["ref-ghost"]["source"] == "app@1",
        str(by_ref),
    )
    _check("missing entry ref recorded", "ref-missing-source" in by_ref, str(by_ref))
    _check(
        "unresolved surfaced as warnings",
        any("未解析依赖" in w and "ref-ghost" in w for w in result["warnings"]),
        str(result["warnings"]),
    )
    _check("status warning due to unresolved", result["status"] == "warning", result["status"])


def test_wrong_bom_format_rejected() -> None:
    result = analyzer.analyze_manifest({"bomFormat": "SPDX", "components": []})
    _check("non-CycloneDX bomFormat -> error", result["status"] == "error")
    _check("error mentions bomFormat", "bomFormat" in result["error"], result["error"])


def test_display_name_from_metadata() -> None:
    bom = _bom(
        [_comp("r1", "lib", "1", [{"license": {"id": "MIT"}}])],
        metadata={"component": {"type": "application", "name": "shop-backend"}},
    )
    result = analyzer.analyze_manifest(bom)
    _check("metadata.component.name used", result["manifest_name"] == "shop-backend", result["manifest_name"])
    named = analyzer.analyze_manifest(_bom([], name="explicit-name"))
    _check("explicit name wins", named["manifest_name"] == "explicit-name")


def test_history_and_export_roundtrip() -> None:
    result = analyzer.analyze_manifest(_demo_bom(), "cyclonedx-demo")
    audit_id = database.save_audit(result, _demo_bom())
    result["audit_id"] = audit_id

    items = database.list_audits(10)
    brief = next((i for i in items if i["id"] == audit_id), None)
    _check("cyclonedx audit appears in history", brief is not None, str(items))
    _check("history brief keeps counts", brief["package_count"] == 3 and brief["conflict_count"] >= 1, str(brief))

    loaded = database.get_audit(audit_id)
    _check("stored result keeps source_format", loaded.get("source_format") == "cyclonedx")
    _check("stored result keeps nodes+edges", len(loaded["nodes"]) == 3 and len(loaded["edges"]) == 2)

    filtered = analyzer.filter_result(loaded, "lib")
    _check(
        "filter works on cyclonedx result",
        filtered["filtered"] and any(n["id"] == "lib@2.0.0" for n in filtered["nodes"]),
    )

    other = analyzer.analyze_manifest(_demo_bom(), "cyclonedx-demo-2")
    other_id = database.save_audit(other, _demo_bom())
    comparison = compare_mod.compare_audits(database.get_audit(audit_id), database.get_audit(other_id))
    _check(
        "compare works on cyclonedx audits",
        comparison["summary"]["findings"]["added"] == 0
        and comparison["summary"]["findings"]["removed"] == 0,
        str(comparison["summary"]),
    )


def main() -> None:
    test_detection()
    test_basic_import_and_conflicts()
    test_bom_ref_mapping()
    test_license_sources()
    test_same_component_merges_when_license_agrees()
    test_duplicate_bom_ref_rejected()
    test_conflicting_license_rejected()
    test_unresolved_refs_kept_as_warnings()
    test_wrong_bom_format_rejected()
    test_display_name_from_metadata()
    test_history_and_export_roundtrip()
    print("\nall tests passed.")


if __name__ == "__main__":
    main()
