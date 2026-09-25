"""多许可证候选判定的轻量自测（无测试框架依赖）：python -m tests.test_multi_license

覆盖：

* 纯 OR 表达式与多个并列许可证条目的候选解析（原生 manifest / CycloneDX）；
* 含 AND、括号、未知标识的表达式仍按未知处理；
* 祖先与依赖各有候选时的组合判定：全冲突才硬冲突、全兼容才通过、其余需人工确认；
* 单许可证结果与历史语义完全一致。
"""

from __future__ import annotations

from app import analyzer, licenses as lic


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


# --- 候选解析 ----------------------------------------------------------------


def test_parse_or_expression() -> None:
    info = lic.parse_license_entries("MIT OR Apache-2.0")
    _check(
        "OR expression -> candidates",
        info["multi"] and [c["token"] for c in info["candidates"]] == ["MIT", "Apache-2.0"],
        str(info),
    )
    _check("OR display preserved", info["display"] == "MIT OR Apache-2.0")
    _check("OR token canonical", info["token"] == "MIT OR Apache-2.0")
    _check("OR category multi", info["category"] == lic.MULTI)
    # OR 大小写不敏感
    info_lower = lic.parse_license_entries("mit or apache 2")
    _check(
        "lowercase or accepted with aliases",
        info_lower["multi"]
        and [c["token"] for c in info_lower["candidates"]] == ["MIT", "Apache-2.0"],
        str(info_lower),
    )


def test_parse_parallel_entries() -> None:
    info = lic.parse_license_entries(
        [{"license": {"id": "MIT"}}, {"license": {"id": "Apache-2.0"}}]
    )
    _check(
        "parallel id entries -> candidates",
        info["multi"] and [c["token"] for c in info["candidates"]] == ["MIT", "Apache-2.0"],
        str(info),
    )
    # 字符串形式的并列条目（原生 manifest 同样接受）
    info2 = lic.parse_license_entries(["MIT", "Apache 2.0"])
    _check(
        "parallel string entries -> candidates",
        info2["multi"] and [c["token"] for c in info2["candidates"]] == ["MIT", "Apache-2.0"],
        str(info2),
    )
    # 重复候选去重
    info3 = lic.parse_license_entries(["MIT", "MIT License", "MIT OR MIT"])
    _check(
        "duplicate candidates dedupe",
        not info3["multi"] and [c["token"] for c in info3["candidates"]] == ["MIT"],
        str(info3),
    )
    # 表达式与并列条目混合：候选取并集
    info4 = lic.parse_license_entries(["MIT OR ISC", {"license": {"id": "MIT"}}])
    _check(
        "expression + entry union",
        info4["multi"] and [c["token"] for c in info4["candidates"]] == ["MIT", "ISC"],
        str(info4),
    )


def test_complex_expressions_stay_unknown() -> None:
    for raw in (
        "MIT AND GPL-3.0",
        "mit and gpl-3.0",
        "(MIT OR ISC)",
        "MIT OR OFL-1.1",
        "MIT OR Apache-2.0 AND GPL-3.0",
        ["MIT", "OFL-1.1"],  # 并列条目中含未知标识 -> 整体未知
    ):
        info = lic.parse_license_entries(raw)
        _check(
            "%r stays unknown single" % raw,
            info["known"] is False and info["multi"] is False,
            str(info),
        )


def test_single_license_unchanged() -> None:
    info = lic.parse_license_entries("Apache 2.0")
    _check(
        "single license keeps semantics",
        not info["multi"]
        and info["token"] == "Apache-2.0"
        and info["known"]
        and len(info["candidates"]) == 1,
        str(info),
    )
    missing = lic.parse_license_entries(None)
    _check(
        "missing -> UNLICENSED unknown",
        missing["known"] is False and missing["display"] == "UNLICENSED",
    )


# --- 组合判定 ----------------------------------------------------------------


def test_combination_aggregation() -> None:
    # 全冲突
    r = lic.compatibility_candidates(["GPL-2.0", "GPL-3.0"], ["Proprietary"])
    _check("all combos conflict", r["status"] == lic.CONFLICT and len(r["combinations"]) == 2)
    # 全兼容
    r = lic.compatibility_candidates(["MIT", "ISC"], ["MIT", "ISC"])
    _check("all combos ok", r["status"] == lic.OK and len(r["combinations"]) == 4)
    # 混合（GPL-2.0->Apache-2.0 冲突，其余兼容）
    r = lic.compatibility_candidates(["GPL-2.0", "MIT"], ["Apache-2.0", "MIT"])
    _check("mixed combos warning", r["status"] == lic.WARNING)
    statuses = sorted(item["status"] for item in r["combinations"])
    _check("mixed has conflict+ok", statuses == [lic.CONFLICT, lic.OK, lic.OK, lic.OK], str(statuses))
    # 单许可证严格沿用原矩阵判定与原因
    r = lic.compatibility_candidates(["GPL-2.0"], ["Apache-2.0"])
    _check(
        "single keeps matrix reason",
        r["status"] == lic.CONFLICT and "专利条款" in r["reason"],
        r["reason"],
    )


# --- 端到端审计 --------------------------------------------------------------


def _manifest(parent_license, dep_license):
    return {
        "name": "t",
        "packages": [
            {"name": "app", "version": "1", "license": parent_license,
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": dep_license},
        ],
    }


def test_end_to_end_all_conflict() -> None:
    result = analyzer.analyze_manifest(
        _manifest(["GPL-2.0", "GPL-3.0"], "Proprietary")
    )
    _check("status conflict", result["status"] == "conflict", result["status"])
    conflict = result["conflicts"][0]
    _check("hard conflict severity", conflict["severity"] == "error")
    _check(
        "combination counts listed",
        conflict["combination_counts"] == {"total": 2, "ok": 0, "conflict": 2, "warning": 0},
        str(conflict.get("combination_counts")),
    )
    _check(
        "each combination has verdict + reason",
        len(conflict["candidate_combinations"]) == 2
        and all({"parent", "dep", "status", "reason"} <= set(item)
                for item in conflict["candidate_combinations"]),
    )
    _check("path kept", conflict["path"] == ["app@1", "lib@1"], str(conflict["path"]))


def test_end_to_end_all_ok() -> None:
    result = analyzer.analyze_manifest(_manifest(["MIT", "ISC"], "MIT OR ISC"))
    _check("status clean", result["status"] == "clean", result["status"])
    _check("no conflict entry", result["conflicts"] == [])


def test_end_to_end_mixed_warning() -> None:
    result = analyzer.analyze_manifest(_manifest("GPL-2.0 OR MIT", "Apache-2.0"))
    _check("status warning", result["status"] == "warning", result["status"])
    conflict = result["conflicts"][0]
    _check("mixed is human-review warning", conflict["severity"] == "warning")
    _check(
        "two combinations enumerated with path",
        len(conflict["candidate_combinations"]) == 2 and conflict["distance"] == 1,
        str(conflict),
    )
    _check("ancestor marked multi", conflict["ancestor_multi"] is True)
    _check("node not multi", conflict["node_multi"] is False)


def test_transitive_path_with_candidates() -> None:
    manifest = {
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-2.0 OR MIT",
             "dependencies": ["mid@1"]},
            {"name": "mid", "version": "1", "license": "MIT",
             "dependencies": ["leaf@1"]},
            {"name": "leaf", "version": "1", "license": "Proprietary"},
        ],
    }
    result = analyzer.analyze_manifest(manifest)
    # app -> leaf 传递：GPL-2.0->Proprietary 冲突；MIT->Proprietary 告警；混合 warning
    direct = [
        c for c in result["conflicts"]
        if c["ancestor"] == "app@1" and c["node"] == "leaf@1"
    ]
    _check("one app->leaf finding", len(direct) == 1)
    _check("transitive mixed warning", direct[0]["severity"] == "warning")
    _check(
        "shortest path via mid",
        direct[0]["path"] == ["app@1", "mid@1", "leaf@1"] and direct[0]["distance"] == 2,
        str(direct[0]["path"]),
    )


def test_cyclonedx_or_and_parallel() -> None:
    from app import cyclonedx

    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "a", "name": "app", "version": "1",
             "licenses": [{"expression": "GPL-2.0 OR MIT"}]},
            {"bom-ref": "l", "name": "lib", "version": "1",
             "licenses": [
                 {"license": {"id": "MIT"}},
                 {"license": {"id": "Apache-2.0"}},
             ]},
        ],
        "dependencies": [{"ref": "a", "dependsOn": ["l"]}],
    }
    result = analyzer.analyze_manifest(bom)
    _check("cyclonedx detected", result.get("source_format") == "cyclonedx")
    app = next(n for n in result["nodes"] if n["id"] == "app@1")
    lib = next(n for n in result["nodes"] if n["id"] == "lib@1")
    _check("app OR candidates", app["license_tokens"] == ["GPL-2.0", "MIT"], str(app))
    _check("lib parallel candidates", lib["license_tokens"] == ["MIT", "Apache-2.0"], str(lib))
    # GPL-2.0->Apache 冲突，其他三个组合兼容 -> warning（非硬冲突）
    _check("cyclonedx mixed warning", result["status"] == "warning", result["status"])
    # 同名同版本但以不同写法声明相同候选集合时允许合并
    bom2 = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "x1", "name": "x", "version": "1",
             "licenses": [{"expression": "MIT OR Apache-2.0"}]},
            {"bom-ref": "x2", "name": "x", "version": "1",
             "licenses": [
                 {"license": {"id": "Apache-2.0"}},
                 {"license": {"id": "MIT"}},
             ]},
        ],
    }
    merged = analyzer.analyze_manifest(bom2)
    _check(
        "same candidate set merges",
        merged["status"] != "error" and merged["summary"]["packages"] == 1,
        str(merged.get("error")),
    )
    # 候选集合不同仍拒绝
    bom3 = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "y1", "name": "y", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}]},
            {"bom-ref": "y2", "name": "y", "version": "1",
             "licenses": [{"license": {"id": "GPL-3.0"}}]},
        ],
    }
    _check("different candidates rejected", analyzer.analyze_manifest(bom3)["status"] == "error")


def main() -> None:
    test_parse_or_expression()
    test_parse_parallel_entries()
    test_complex_expressions_stay_unknown()
    test_single_license_unchanged()
    test_combination_aggregation()
    test_end_to_end_all_conflict()
    test_end_to_end_all_ok()
    test_end_to_end_mixed_warning()
    test_transitive_path_with_candidates()
    test_cyclonedx_or_and_parallel()
    print("\nall tests passed.")


if __name__ == "__main__":
    main()
