"""全图许可证选定的自测（无测试框架依赖）：python -m tests.test_graphpick

使用独立临时 SQLite 库验证只读性，不触碰 ./data；
核心逻辑只依赖 analyzer/cyclonedx/database/graphpick，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, cyclonedx, database, graphpick, reviews

# 隔离的临时数据库（仅用于只读性验证）
_TMP_DIR = tempfile.mkdtemp(prefix="graphpick-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _analyze(packages, **kw):
    return analyzer.analyze_manifest({"name": "graphpick-demo", "packages": packages, **kw})


# --- 三级结论 ----------------------------------------------------------------


def test_compatible_with_or_choice() -> None:
    # app(GPL-2.0 OR MIT) -> lib(Apache-2.0)：选 MIT 后全图兼容
    result = _analyze([
        {"name": "app", "version": "1", "license": "GPL-2.0 OR MIT",
         "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": "Apache-2.0"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("kind", report["kind"] == graphpick.KIND)
    _check("read only flag", report["read_only"] is True)
    _check("conclusion compatible", report["conclusion"] == graphpick.COMPATIBLE)
    _check("conclusion label", report["conclusion_label"] == "全图兼容")
    chosen = {s["id"]: s for s in report["selections"]}
    _check("app fixed to MIT", chosen["app@1"]["selected_license"] == "MIT")
    _check("app chosen from candidate", chosen["app@1"]["selected_from"] == "candidate")
    _check("app not fixed single", chosen["app@1"]["fixed"] is False)
    _check("lib single fixed", chosen["lib@1"]["fixed"] is True)
    _check("lib selected itself", chosen["lib@1"]["selected_license"] == "Apache-2.0")
    _check("candidates in declared order",
           chosen["app@1"]["candidates"] == ["GPL-2.0", "MIT"])
    s = report["summary"]
    _check("one multi package", s["multi_license_packages"] == 1)
    _check("two decided packages", s["decided_packages"] == 2)
    _check("no undetermined packages", s["undetermined_packages"] == 0)
    _check("one reachable relation", s["reachable_relations"] == 1)
    _check("one direct relation", s["direct_relations"] == 1)
    _check("zero transitive", s["transitive_relations"] == 0)
    _check("one ok relation", s["ok_relations"] == 1)
    _check("no warning/conflict/undetermined relations",
           s["warning_relations"] == 0 and s["hard_conflict_relations"] == 0
           and s["undetermined_relations"] == 0)
    _check("search not truncated", report["search"]["truncated"] is False)


def test_compatible_transitive_chain() -> None:
    # a(GPL-2.0 OR MIT) -> b(Apache-2.0) -> c(GPL-3.0)：
    # a 必须选 MIT（GPL-2.0 与 Apache-2.0 冲突），其余关系全兼容
    result = _analyze([
        {"name": "a", "version": "1", "license": "GPL-2.0 OR MIT",
         "dependencies": ["b@1"]},
        {"name": "b", "version": "1", "license": "Apache-2.0",
         "dependencies": ["c@1"]},
        {"name": "c", "version": "1", "license": "GPL-3.0"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("chain compatible", report["conclusion"] == graphpick.COMPATIBLE, str(report["summary"]))
    chosen = {s["id"]: s["selected_license"] for s in report["selections"]}
    _check("a selected MIT transitively", chosen["a@1"] == "MIT", str(chosen))
    s = report["summary"]
    _check("three reachable relations", s["reachable_relations"] == 3)  # a->b, a->c, b->c
    _check("two direct relations", s["direct_relations"] == 2)
    _check("one transitive relation", s["transitive_relations"] == 1)
    _check("three ok relations", s["ok_relations"] == 3)


def test_needs_confirmation_warning_only() -> None:
    # app(MIT) -> lib(Proprietary)：矩阵 warning（授权），无候选可选，无法全兼容也无硬冲突
    result = _analyze([
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": "Proprietary"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("needs confirmation", report["conclusion"] == graphpick.NEEDS_CONFIRMATION)
    _check("one warning relation", report["summary"]["warning_relations"] == 1)
    _check("zero hard conflicts", report["summary"]["hard_conflict_relations"] == 0)
    rel = report["relations"]["warnings"][0]
    _check("warning pair", (rel["ancestor"], rel["node"]) == ("app@1", "lib@1"))
    _check("warning shortest path", rel["shortest_path"] == ["app@1", "lib@1"])
    _check("warning direct", rel["direct"] is True)
    _check("warning reason present", bool(rel["reason"]))
    stages = {st["stage"]: st["found"] for st in report["search"]["stages"]}
    _check("all-compatible stage failed", stages["all-compatible"] is False)
    _check("avoid stage succeeded", stages["avoid-hard-conflict"] is True)
    _check("warning message mentions manual confirm",
           any("需人工确认" in w for w in report["warnings"]))


def test_unknown_license_blocks_compatible_claim() -> None:
    # 已判定关系全兼容，但图中含未知许可证包：必须降级为需人工确认，不能声称全图可行
    result = _analyze([
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": "ISC", "dependencies": ["u@1"]},
        {"name": "u", "version": "1", "license": "OFL-1.1"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("downgraded to needs confirmation",
           report["conclusion"] == graphpick.NEEDS_CONFIRMATION)
    chosen = {s["id"]: s for s in report["selections"]}
    _check("unknown package marked", chosen["u@1"]["undetermined"] is True)
    _check("unknown package no selection", chosen["u@1"]["selected_license"] is None)
    _check("unknown reason given", "未在兼容矩阵中识别" in chosen["u@1"]["undetermined_reason"])
    _check("one undetermined package", report["summary"]["undetermined_packages"] == 1)
    _check("two undetermined relations", report["summary"]["undetermined_relations"] == 2)
    pairs = {(r["ancestor"], r["node"]) for r in report["relations"]["undetermined"]}
    _check("undetermined pairs", pairs == {("app@1", "u@1"), ("lib@1", "u@1")}, str(pairs))
    rel = next(r for r in report["relations"]["undetermined"]
               if (r["ancestor"], r["node"]) == ("lib@1", "u@1"))
    _check("undetermined carries shortest path",
           rel["shortest_path"] == ["lib@1", "u@1"])
    _check("undetermined status token", rel["status"] == graphpick.REL_UNDETERMINED)
    _check("unknown warning emitted", any("未知" in w for w in report["warnings"]))


def test_unlicensed_node_marked_undetermined() -> None:
    result = _analyze([
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["noname@1"]},
        {"name": "noname", "version": "1"},
    ])
    report = graphpick.select_graph_licenses(result)
    chosen = {s["id"]: s for s in report["selections"]}
    _check("unlicensed node undetermined", chosen["noname@1"]["undetermined"] is True)
    _check("unlicensed reason", chosen["noname@1"]["undetermined_reason"] ==
           "节点未声明许可证（UNLICENSED）")
    _check("downgraded", report["conclusion"] == graphpick.NEEDS_CONFIRMATION)


def test_unresolved_dependency_blocks_compatible_claim() -> None:
    # 无任何许可证冲突，但有未解析依赖：不能声称全图可行
    result = _analyze([
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["ghost@9"]},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("needs confirmation due to unresolved",
           report["conclusion"] == graphpick.NEEDS_CONFIRMATION)
    _check("one unresolved", report["summary"]["unresolved_dependencies"] == 1)
    _check("unresolved carried", report["unresolved"][0]["reference"] == "ghost@9")
    _check("unresolved warning emitted",
           any("未解析依赖" in w for w in report["warnings"]))


def test_unsolvable_single_conflict() -> None:
    # app(GPL-2.0) -> lib(Apache-2.0)：唯一选择即硬冲突
    result = _analyze([
        {"name": "app", "version": "1", "license": "GPL-2.0", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": "Apache-2.0"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("unsolvable", report["conclusion"] == graphpick.UNSOLVABLE)
    _check("unsolvable label", "无解" in report["conclusion_label"])
    _check("one hard conflict", report["summary"]["hard_conflict_relations"] == 1)
    rel = report["relations"]["hard_conflicts"][0]
    _check("conflict pair", (rel["ancestor"], rel["node"]) == ("app@1", "lib@1"))
    _check("conflict status", rel["status"] == "conflict")
    _check("conflict path", rel["shortest_path"] == ["app@1", "lib@1"])
    _check("unsolvable warning", any("无解" in w for w in report["warnings"]))
    min_stage = report["search"]["stages"][-1]
    _check("minimum conflicts reported", min_stage["minimum_hard_conflicts"] == 1)


def test_unsolvable_transitive_no_choice_helps() -> None:
    # a(GPL-2.0) -> b(Apache-2.0) -> c(MIT)；b 是多候选 [Apache-2.0, GPL-2.0]：
    # 选 Apache：a->b 冲突；选 GPL-2.0：b->? 无冲突但 a(GPL-2.0)->b(GPL-2.0) 兼容，
    # 这里构造真正无解：a(GPL-2.0) -> b(Apache-2.0 OR GPL-3.0)
    #   b=Apache-2.0 -> a->b 冲突；b=GPL-3.0 -> a->b 冲突（GPL2 不能升 GPL3）
    result = _analyze([
        {"name": "a", "version": "1", "license": "GPL-2.0", "dependencies": ["b@1"]},
        {"name": "b", "version": "1", "license": "Apache-2.0 OR GPL-3.0"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("unsolvable despite multi choice",
           report["conclusion"] == graphpick.UNSOLVABLE, str(report["conclusion"]))
    _check("minimum one conflict", report["summary"]["hard_conflict_relations"] == 1)
    _check("still gives a selection per package",
           all(s["selected_license"] for s in report["selections"]
               if not s["undetermined"]))


def test_minimize_picks_least_conflicts() -> None:
    # p(GPL-2.0 OR MIT) -> x(Apache-2.0)；p->y(Apache-2.0)：
    # 选 GPL-2.0 有 2 条硬冲突，选 MIT 0 条——本应 compatible；
    # 改为强制无解：p(GPL-2.0 OR GPL-3.0) -> x(Apache-2.0)（GPL3 兼容 Apache）
    # 选 GPL-2.0 = 1 冲突，选 GPL-3.0 = 0 冲突 => compatible 且选 GPL-3.0
    result = _analyze([
        {"name": "p", "version": "1", "license": "GPL-2.0 OR GPL-3.0",
         "dependencies": ["x@1"]},
        {"name": "x", "version": "1", "license": "Apache-2.0"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("GPL-3.0 choice makes compatible",
           report["conclusion"] == graphpick.COMPATIBLE)
    chosen = {s["id"]: s["selected_license"] for s in report["selections"]}
    _check("p chose GPL-3.0", chosen["p@1"] == "GPL-3.0")


def test_cycle_is_safe() -> None:
    result = _analyze([
        {"name": "a", "version": "1", "license": "MIT", "dependencies": ["b@1"]},
        {"name": "b", "version": "1", "license": "ISC", "dependencies": ["a@1"]},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("cycle safe and compatible", report["conclusion"] == graphpick.COMPATIBLE)
    _check("cycle relations", report["summary"]["reachable_relations"] == 2)


def test_deterministic() -> None:
    result = _analyze([
        {"name": "a", "version": "1", "license": "MIT OR ISC", "dependencies": ["b@1"]},
        {"name": "b", "version": "1", "license": "ISC OR MIT"},
    ])
    r1 = graphpick.select_graph_licenses(result)
    r2 = graphpick.select_graph_licenses(result)
    s1 = {s["id"]: s["selected_license"] for s in r1["selections"]}
    s2 = {s["id"]: s["selected_license"] for s in r2["selections"]}
    _check("deterministic selections", s1 == s2, str((s1, s2)))


def test_empty_audit() -> None:
    result = analyzer.analyze_manifest({"name": "empty"})
    report = graphpick.select_graph_licenses(result)
    _check("empty audit compatible", report["conclusion"] == graphpick.COMPATIBLE)
    _check("no relations", report["summary"]["reachable_relations"] == 0)


def test_parallel_entries_treated_as_candidates() -> None:
    # 多个并列许可证条目（数组形式）同样成为候选
    result = _analyze([
        {"name": "app", "version": "1", "license": ["GPL-2.0", "MIT"],
         "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": "Apache-2.0"},
    ])
    report = graphpick.select_graph_licenses(result)
    _check("parallel entries compatible", report["conclusion"] == graphpick.COMPATIBLE)
    chosen = {s["id"]: s for s in report["selections"]}
    _check("parallel candidates", chosen["app@1"]["candidates"] == ["GPL-2.0", "MIT"])
    _check("parallel selected MIT", chosen["app@1"]["selected_license"] == "MIT")


def test_search_budget_truncation_reported() -> None:
    result = _analyze([
        {"name": "app", "version": "1", "license": "GPL-2.0", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": "Apache-2.0"},
    ])
    report = graphpick.select_graph_licenses(result, search_budget=0)
    _check("still unsolvable under budget", report["conclusion"] == graphpick.UNSOLVABLE)
    _check("truncated flagged", report["search"]["truncated"] is True)
    _check("truncation warning", any("预算" in w for w in report["warnings"]))
    # 即便截断也给出一份完整选择供定位
    _check("fallback selection present",
           all(s["selected_license"] for s in report["selections"]
               if not s["undetermined"]))
    _check("fallback still lists conflict",
           report["summary"]["hard_conflict_relations"] == 1)


def test_truncated_zero_conflict_assignment_not_called_unsolvable() -> None:
    # 预算为 0：前两阶段均无法判定；最少化阶段的首个候选组合恰好 0 硬冲突时，
    # 结论必须是需人工确认（且标注截断），不能误判为无解或全图兼容。
    result = _analyze([
        {"name": "app", "version": "1", "license": "MIT OR GPL-2.0",
         "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": "Apache-2.0"},
    ])
    report = graphpick.select_graph_licenses(result, search_budget=0)
    _check("truncated flagged", report["search"]["truncated"] is True)
    _check("not unsolvable when zero-conflict assignment found",
           report["conclusion"] != graphpick.UNSOLVABLE, report["conclusion"])
    _check("downgraded to needs confirmation",
           report["conclusion"] == graphpick.NEEDS_CONFIRMATION)
    _check("zero hard conflicts in returned assignment",
           report["summary"]["hard_conflict_relations"] == 0)
    # 充足预算下同一审计本就是全兼容
    full = graphpick.select_graph_licenses(result)
    _check("full search compatible", full["conclusion"] == graphpick.COMPATIBLE)


def test_cyclonedx_supported() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "app", "name": "app", "version": "1",
             "licenses": [{"expression": "GPL-2.0 OR MIT"}]},
            {"bom-ref": "lib", "name": "lib", "version": "1",
             "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["lib"]}],
    }
    result = cyclonedx.analyze_bom(bom)
    report = graphpick.select_graph_licenses(result)
    _check("cyclonedx compatible", report["conclusion"] == graphpick.COMPATIBLE)
    _check("cyclonedx audit meta", report["audit"]["source_format"] == "cyclonedx")
    chosen = {s["id"]: s["selected_license"] for s in report["selections"]}
    _check("cyclonedx chose MIT", chosen["app@1"] == "MIT")


def test_read_only() -> None:
    manifest = {
        "name": "ro-demo",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-2.0",
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "Apache-2.0"},
        ],
    }
    result = analyzer.analyze_manifest(manifest)
    audit_id = database.save_audit(result, manifest)
    stored = database.get_audit(audit_id)
    conflict = stored["conflicts"][0]
    database.save_review(
        fingerprint=reviews.fingerprint_for_conflict(stored, conflict),
        ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-2.0", node_license="Apache-2.0",
        note="全图选定不应改动我",
    )
    stored_before = database.get_audit(audit_id)
    audits_before = database.list_audits(limit=500)
    reviews_before = database.list_reviews(limit=500)
    snapshot = copy.deepcopy(stored_before)

    report = graphpick.select_graph_licenses(stored_before)
    _check("report produced", report["read_only"] is True)
    _check("input not mutated", stored_before == snapshot)
    _check("no audit created", database.list_audits(limit=500) == audits_before)
    _check("stored audit unchanged", database.get_audit(audit_id) == snapshot)
    _check("reviews untouched", database.list_reviews(limit=500) == reviews_before)


def main() -> None:
    test_compatible_with_or_choice()
    test_compatible_transitive_chain()
    test_needs_confirmation_warning_only()
    test_unknown_license_blocks_compatible_claim()
    test_unlicensed_node_marked_undetermined()
    test_unresolved_dependency_blocks_compatible_claim()
    test_unsolvable_single_conflict()
    test_unsolvable_transitive_no_choice_helps()
    test_minimize_picks_least_conflicts()
    test_cycle_is_safe()
    test_deterministic()
    test_empty_audit()
    test_parallel_entries_treated_as_candidates()
    test_search_budget_truncation_reported()
    test_truncated_zero_conflict_assignment_not_called_unsolvable()
    test_cyclonedx_supported()
    test_read_only()
    print("\nall graphpick tests passed.")


if __name__ == "__main__":
    main()
