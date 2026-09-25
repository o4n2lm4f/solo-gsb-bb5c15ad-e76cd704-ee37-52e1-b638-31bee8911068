"""未解析依赖补边预演的自测（无测试框架依赖）：python -m tests.test_edgefix

使用独立临时 SQLite 库验证只读性，不触碰 ./data；
核心逻辑只依赖 analyzer/cyclonedx/compare/edgefix，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, cyclonedx, database, edgefix, reviews

# 隔离的临时数据库（仅用于只读性验证）
_TMP_DIR = tempfile.mkdtemp(prefix="edgefix-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _demo_manifest():
    # app(GPL-2.0) -> lib(Apache-2.0) 是硬冲突；app 经 mid 传递约束 deep（2 跳硬冲突）。
    # 未解析项：app -> pay@2 / deep@2（精确版本未声明）、mid -> cache-redis（包未声明）。
    return {
        "name": "edgefix-demo",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-2.0",
             "dependencies": ["lib@1", "mid@1", "pay@2", "deep@2"]},
            {"name": "lib", "version": "1", "license": "Apache-2.0"},
            {"name": "mid", "version": "1", "license": "MIT",
             "dependencies": ["deep@1", "cache-redis"]},
            {"name": "deep", "version": "1", "license": "Apache-2.0"},
            {"name": "pay", "version": "1", "license": "Apache-2.0"},
        ],
    }


def _demo_result():
    return analyzer.analyze_manifest(_demo_manifest())


def _expect_error(name: str, fn, needle: str) -> None:
    try:
        fn()
    except ValueError as exc:
        _check(name, needle in str(exc), "message=%r" % str(exc))
        return
    raise AssertionError("%s 未抛出 ValueError" % name)


def test_preview_lists_selectable_unresolved() -> None:
    result = _demo_result()
    report = edgefix.rehearse_edgefix(result)
    _check("preview not rehearsed", report["rehearsed"] is False)
    _check("preview read only", report["read_only"] is True)
    _check("preview summary empty", report["summary"] is None)
    _check("preview comparison empty", report["comparison"] is None)
    _check("preview remaining empty", report["remaining_unresolved"] is None)
    items = [(u["source"], u["reference"]) for u in report["unresolved"]]
    _check(
        "preview lists all source-existing unresolved",
        items == [("app@1", "pay@2"), ("app@1", "deep@2"), ("mid@1", "cache-redis")],
        str(items),
    )
    app_item = report["unresolved"][0]
    _check(
        "existing targets listed for duplicate filtering",
        app_item["existing_targets"] == ["lib@1", "mid@1"],
        str(app_item),
    )
    _check("nothing skipped", report["unresolved_skipped"] == [])
    _check(
        "packages listed as targets",
        [p["id"] for p in report["packages"]] == ["app@1", "lib@1", "mid@1", "deep@1", "pay@1"],
    )
    pay = report["packages"][4]
    _check("package brief carries license", pay["license"] == "Apache-2.0" and pay["license_known"])


def test_preview_skips_missing_source() -> None:
    # 顶层 dependencies 的源包未声明时，未解析项的 source 为 "?"，不可补边
    result = analyzer.analyze_manifest({
        "packages": [{"name": "app", "version": "1", "license": "MIT"}],
        "dependencies": {"ghost@1": ["app@1"]},
    })
    _check("unresolved recorded", len(result["unresolved"]) == 1, str(result["unresolved"]))
    report = edgefix.rehearse_edgefix(result)
    _check("missing-source item not selectable", report["unresolved"] == [])
    _check(
        "missing-source item reported as skipped",
        [(u["source"], u["reference"]) for u in report["unresolved_skipped"]] == [("?", "ghost@1")],
        str(report["unresolved_skipped"]),
    )
    _expect_error(
        "missing-source reference rejected",
        lambda: edgefix.rehearse_edgefix(result, "?", "ghost@1", "app@1"),
        "源包不在该审计的节点中",
    )


def test_edgefix_adds_conflict() -> None:
    result = _demo_result()
    report = edgefix.rehearse_edgefix(result, "app@1", "pay@2", "pay@1")
    _check("rehearsed flag", report["rehearsed"] is True)
    fix = report["fix"]
    _check("fix source", fix["source"] == "app@1")
    _check("fix reference", fix["reference"] == "pay@2")
    _check("fix target", fix["target"] == "pay@1")
    _check(
        "fix edge recorded",
        fix["edge"] == {"source": "app@1", "target": "pay@1", "from": "edgefix-rehearsal"},
        str(fix["edge"]),
    )

    s = report["summary"]
    _check("conflicts 2 -> 3", (s["conflicts_before"], s["conflicts_after"]) == (2, 3), str(s))
    _check("conflicts net +1", s["conflicts_net"] == 1)
    _check("total net +1", s["total_net"] == 1)
    _check("unresolved 3 -> 2", (s["unresolved_before"], s["unresolved_after"]) == (3, 2), str(s))
    _check("unresolved net -1", s["unresolved_net"] == -1)
    _check("added counted", s["added"] == 1 and s["added_errors"] == 1)
    _check("nothing removed", s["removed"] == 0)
    _check("no path change", s["path_changed"] == 0)

    cmp = report["comparison"]
    _check("one added finding", len(cmp["added"]) == 1, str(cmp["added"]))
    added = cmp["added"][0]
    _check("added pair app->pay", (added["ancestor"], added["node"]) == ("app@1", "pay@1"))
    _check("added base side null", added["base"] is None)
    _check("added carries rehearsal path", added["target"]["path"] == ["app@1", "pay@1"])
    _check("added is error", added["severity_target"] == "error")
    # 原有冲突不受影响，不出现在任何变化列表
    keys = {(f["ancestor"], f["node"]) for bucket in (cmp["added"], cmp["removed"], cmp["changed"])
            for f in bucket}
    _check("untouched conflicts omitted", ("app@1", "lib@1") not in keys and ("app@1", "deep@1") not in keys)

    rest = [(u["source"], u["reference"]) for u in report["remaining_unresolved"]]
    _check(
        "chosen unresolved removed, others kept",
        rest == [("app@1", "deep@2"), ("mid@1", "cache-redis")],
        str(rest),
    )
    # 预演结果的未解析告警同步减少，且其余节点/许可证/边保留
    rehearsal_warnings = report["comparison"]["target"]["manifest_name"]
    _check("rehearsal meta named", "补边 app@1 -> pay@1" in rehearsal_warnings, str(rehearsal_warnings))
    _check("rehearsal status conflict", report["rehearsal"]["status"] == "conflict")
    _check("rehearsal edges +1", report["rehearsal"]["edges"] == 4, str(report["rehearsal"]))


def test_edgefix_nodes_and_licenses_preserved() -> None:
    result = _demo_result()
    report = edgefix.rehearse_edgefix(result, "app@1", "pay@2", "pay@1")
    pairs = {n["id"]: n for n in report["comparison"]["nodes"]}
    _check("all nodes paired unchanged",
           all(n["change"] == "unchanged" for n in pairs.values()), str(pairs))
    _check("no license changed",
           not any(n["license_changed"] for n in pairs.values()))
    # 目标包许可证保持原样（补边不改动任何节点许可证）
    _check("target license preserved", pairs["pay@1"]["target"]["license"] == "Apache-2.0")


def test_edgefix_shortens_conflict_path() -> None:
    # 原冲突 app->deep 最短路径 2 跳（app->mid->deep）；补 app->deep 直达边后缩短为 1 跳
    result = _demo_result()
    report = edgefix.rehearse_edgefix(result, "app@1", "deep@2", "deep@1")
    s = report["summary"]
    _check("conflict count unchanged", s["conflicts_net"] == 0, str(s))
    _check("no added/removed", s["added"] == 0 and s["removed"] == 0)
    _check("one path-changed pair", s["changed"] == 1 and s["path_changed"] == 1, str(s))

    cmp = report["comparison"]
    finding = cmp["changed"][0]
    _check("changed pair app->deep", (finding["ancestor"], finding["node"]) == ("app@1", "deep@1"))
    _check("path flagged", "path" in finding["fields_changed"], str(finding["fields_changed"]))
    _check("path_changed flag", finding["path_changed"] is True)
    _check(
        "base path 2 hops",
        finding["base"]["path"] == ["app@1", "mid@1", "deep@1"] and finding["base"]["distance"] == 2,
        str(finding["base"]),
    )
    _check(
        "rehearsal path 1 hop",
        finding["target"]["path"] == ["app@1", "deep@1"] and finding["target"]["distance"] == 1,
        str(finding["target"]),
    )
    _check("severity unchanged", finding["severity_base"] == "error" == finding["severity_target"])
    rest = [(u["source"], u["reference"]) for u in report["remaining_unresolved"]]
    _check("remaining unresolved", rest == [("app@1", "pay@2"), ("mid@1", "cache-redis")], str(rest))


def test_edgefix_warning_via_new_edge() -> None:
    # 目标包许可证未知时，补边产生的是“需人工确认”告警而非硬冲突
    result = analyzer.analyze_manifest({
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["x@2"]},
            {"name": "x", "version": "1", "license": "OFL-1.1"},
        ],
    })
    _check("originally clean", result["summary"]["conflicts"] == 0
           and result["summary"]["license_warnings"] == 0, str(result["summary"]))
    report = edgefix.rehearse_edgefix(result, "app@1", "x@2", "x@1")
    s = report["summary"]
    _check("warning added", s["warnings_net"] == 1 and s["conflicts_net"] == 0, str(s))
    _check("added is warning not error", s["added"] == 1 and s["added_errors"] == 0)
    added = report["comparison"]["added"][0]
    _check("warning pair", (added["ancestor"], added["node"]) == ("app@1", "x@1"))
    _check("warning severity", added["severity_target"] == "warning")


def test_target_resolution() -> None:
    result = _demo_result()
    # id 大小写不敏感
    report = edgefix.rehearse_edgefix(result, "app@1", "pay@2", "Pay@1")
    _check("target id matched case-insensitively", report["fix"]["target"] == "pay@1")
    # 包名唯一时可直接给包名
    report = edgefix.rehearse_edgefix(result, "app@1", "pay@2", "pay")
    _check("bare name resolved", report["fix"]["target"] == "pay@1")

    multi = analyzer.analyze_manifest({
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["lib@3"]},
            {"name": "lib", "version": "1", "license": "MIT"},
            {"name": "lib", "version": "2", "license": "GPL-3.0"},
        ],
    })
    _expect_error(
        "ambiguous bare target rejected",
        lambda: edgefix.rehearse_edgefix(multi, "app@1", "lib@3", "lib"),
        "对应多个版本",
    )


def test_validation_errors() -> None:
    result = _demo_result()
    _expect_error(
        "unknown reference rejected",
        lambda: edgefix.rehearse_edgefix(result, "app@1", "nope@9", "pay@1"),
        "不存在未解析引用：app@1 -> nope@9",
    )
    _expect_error(
        "unknown source rejected",
        lambda: edgefix.rehearse_edgefix(result, "ghost@1", "pay@2", "pay@1"),
        "不存在未解析引用：ghost@1 -> pay@2",
    )
    _expect_error(
        "unknown target rejected",
        lambda: edgefix.rehearse_edgefix(result, "app@1", "pay@2", "ghost@9"),
        "审计中不存在目标包：ghost@9",
    )
    _expect_error(
        "self edge rejected",
        lambda: edgefix.rehearse_edgefix(result, "app@1", "pay@2", "app@1"),
        "自依赖",
    )
    _expect_error(
        "duplicate edge rejected",
        lambda: edgefix.rehearse_edgefix(result, "app@1", "pay@2", "lib@1"),
        "已存在",
    )
    _expect_error(
        "reference without target rejected",
        lambda: edgefix.rehearse_edgefix(result, "app@1", "pay@2"),
        "必须同时提供",
    )
    _expect_error(
        "target without reference rejected",
        lambda: edgefix.rehearse_edgefix(result, target="pay@1"),
        "必须同时提供",
    )


def test_cyclonedx_audit_supported() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "app", "name": "app", "version": "1",
             "licenses": [{"license": {"id": "GPL-2.0"}}]},
            {"bom-ref": "lib", "name": "lib", "version": "1",
             "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": ["missing-ref"]},
            {"ref": "ghost", "dependsOn": ["app"]},
        ],
    }
    result = cyclonedx.analyze_bom(bom)
    _check("cyclonedx unresolved recorded", len(result["unresolved"]) == 2, str(result["unresolved"]))
    report = edgefix.rehearse_edgefix(result)
    items = [(u["source"], u["reference"]) for u in report["unresolved"]]
    _check("only source-existing item selectable", items == [("app@1", "missing-ref")], str(items))
    _check("ref-less item skipped",
           [u["source"] for u in report["unresolved_skipped"]] == ["?"])

    report = edgefix.rehearse_edgefix(result, "app@1", "missing-ref", "lib@1")
    _check("cyclonedx rehearsed", report["rehearsed"] is True)
    s = report["summary"]
    _check("cyclonedx conflict added", s["conflicts_net"] == 1, str(s))
    added = report["comparison"]["added"]
    _check("cyclonedx added pair",
           [(a["ancestor"], a["node"]) for a in added] == [("app@1", "lib@1")])
    _check("cyclonedx source_format kept",
           report["rehearsal"]["source_format"] == "cyclonedx", str(report["rehearsal"]))
    _check("cyclonedx remaining unresolved",
           [(u["source"], u["reference"]) for u in report["remaining_unresolved"]]
           == [("?", "ghost")], str(report["remaining_unresolved"]))


def test_rehearsal_is_read_only() -> None:
    manifest = _demo_manifest()
    result = analyzer.analyze_manifest(manifest)
    audit_id = database.save_audit(result, manifest)
    # 先打一条复核标记，确认预演不会改动复核标记
    stored = database.get_audit(audit_id)
    conflict = stored["conflicts"][0]
    database.save_review(
        fingerprint=reviews.fingerprint_for_conflict(stored, conflict),
        ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-2.0", node_license="Apache-2.0", note="预演不应改动我",
    )

    stored_before = database.get_audit(audit_id)
    audits_before = database.list_audits(limit=500)
    reviews_before = database.list_reviews(limit=500)

    snapshot = copy.deepcopy(stored_before)
    report = edgefix.rehearse_edgefix(stored_before, "app@1", "pay@2", "pay@1")
    _check("report produced", report["rehearsed"] is True)
    _check("input result not mutated", stored_before == snapshot)
    _check("no new audit created", database.list_audits(limit=500) == audits_before)
    _check("stored audit unchanged", database.get_audit(audit_id) == snapshot)
    _check("reviews untouched", database.list_reviews(limit=500) == reviews_before)
    _check("missing audit stays missing", database.get_audit(999999) is None)


def main() -> None:
    test_preview_lists_selectable_unresolved()
    test_preview_skips_missing_source()
    test_edgefix_adds_conflict()
    test_edgefix_nodes_and_licenses_preserved()
    test_edgefix_shortens_conflict_path()
    test_edgefix_warning_via_new_edge()
    test_target_resolution()
    test_validation_errors()
    test_cyclonedx_audit_supported()
    test_rehearsal_is_read_only()
    print("\nall edgefix tests passed.")


if __name__ == "__main__":
    main()
