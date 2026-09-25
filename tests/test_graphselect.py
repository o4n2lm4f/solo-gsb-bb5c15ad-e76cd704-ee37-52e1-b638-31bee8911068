"""全图许可证选定的自测（无测试框架依赖）：python -m tests.test_graphselect

使用独立临时 SQLite 库验证只读性，不触碰 ./data；
核心逻辑只依赖 analyzer/cyclonedx/graphselect，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, cyclonedx, database, graphselect as gs, reviews

# 隔离的临时数据库（仅用于只读性验证）
_TMP_DIR = tempfile.mkdtemp(prefix="graphselect-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _manifest(packages, edges=None, unresolved_note=False):
    return {"name": "gs-demo", "packages": packages, "edges": edges or []}


def _sel_map(report):
    return {s["node"]["id"]: s["selected_token"] for s in report["selections"]}


def test_report_envelope() -> None:
    result = analyzer.analyze_manifest(_manifest([
        {"name": "a", "version": "1", "license": "MIT", "dependencies": ["b@1"]},
        {"name": "b", "version": "1", "license": "MIT"},
    ]))
    report = gs.select_graph_licenses(result)
    _check("kind", report["kind"] == "graph-license-selection")
    _check("read only", report["read_only"] is True)
    _check("deterministic", report["deterministic"] is True)
    _check("status feasible", report["status"] == gs.FEASIBLE)
    _check("all compatible", report["summary"]["all_relations_compatible"] is True)
    _check("fully determined", report["summary"]["fully_determined"] is True)
    _check("one relation ok", report["summary"]["relations_ok"] == 1, str(report["summary"]))
    _check("no conflict/warning lists",
           not report["hard_conflict_relations"] and not report["warning_relations"]
           and not report["undetermined_relations"])
    fixed = report["selections"][0]
    _check("single license fixed", fixed["fixed"] is True and fixed["selected_token"] == "MIT")


def test_or_choice_picks_compatible() -> None:
    # app(MIT) -> lib(Apache-2.0 OR GPL-2.0)：两个候选都兼容，取声明顺序首个 Apache-2.0
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": ["Apache-2.0", "GPL-2.0"]},
    ]))
    report = gs.select_graph_licenses(result)
    _check("feasible", report["status"] == gs.FEASIBLE, report["conclusion"])
    _check("lib chosen Apache-2.0", _sel_map(report)["lib@1"] == "Apache-2.0")
    _check("lib not fixed", [s for s in report["selections"] if s["node"]["id"] == "lib@1"][0]["fixed"] is False)
    _check("multi counted", report["summary"]["multi_license_packages"] == 1)


def test_transitive_all_reachable_relations() -> None:
    # app(MIT) -> mid(GPL-2.0 OR MIT) -> deep(Apache-2.0)
    # 全部可达关系 = app->mid, app->deep, mid->deep 三条；mid=MIT 时全兼容。
    # 若只看直接边，mid=GPL-2.0 也会被当作可行（app MIT 容纳），
    # 但 mid->deep 是硬冲突，必须经传递关系排除。
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["mid@1"]},
        {"name": "mid", "version": "1", "license": ["GPL-2.0", "MIT"],
         "dependencies": ["deep@1"]},
        {"name": "deep", "version": "1", "license": "Apache-2.0"},
    ]))
    report = gs.select_graph_licenses(result)
    _check("feasible via MIT", report["status"] == gs.FEASIBLE, report["conclusion"])
    _check("mid must be MIT", _sel_map(report)["mid@1"] == "MIT")
    _check("three relations judged", report["summary"]["relations_ok"] == 3, str(report["summary"]))
    # 传递关系 app -> deep 也纳入判定（2 跳），不是只看直接边
    _check("reachable count 3", report["summary"]["reachable_relations"] == 3)


def test_manual_review_warning_only() -> None:
    # app(Proprietary 固定) -> lib(MPL-2.0 OR GPL-2.0)：
    # Proprietary->MPL-2.0 为 warning（需动态链接），Proprietary->GPL-2.0 硬冲突。
    # 最优选择 MPL-2.0：硬冲突 0、告警 1 => 需人工确认。
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": "Proprietary", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": ["MPL-2.0", "GPL-2.0"]},
    ]))
    report = gs.select_graph_licenses(result)
    _check("manual review", report["status"] == gs.MANUAL_REVIEW, report["conclusion"])
    _check("avoids hard conflicts", report["summary"]["avoids_hard_conflicts"] is True)
    _check("not all compatible", report["summary"]["all_relations_compatible"] is False)
    _check("lib chosen MPL", _sel_map(report)["lib@1"] == "MPL-2.0")
    _check("one warning relation", len(report["warning_relations"]) == 1)
    w = report["warning_relations"][0]
    _check("warning pair", (w["ancestor"], w["node"], w["ancestor_selected"], w["node_selected"])
           == ("app@1", "lib@1", "Proprietary", "MPL-2.0"), str(w))
    _check("no conflict relations", not report["hard_conflict_relations"])


def test_unsolvable_hard_conflict_unavoidable() -> None:
    # app(GPL-2.0 固定) -> lib(Apache-2.0 OR GPL-3.0)：两个候选都与 GPL-2.0 硬冲突。
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": "GPL-2.0", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": ["Apache-2.0", "GPL-3.0"]},
    ]))
    report = gs.select_graph_licenses(result)
    _check("unsolvable", report["status"] == gs.UNSOLVABLE, report["conclusion"])
    _check("judged outcome unsolvable", report["judged_outcome"] == gs.UNSOLVABLE)
    _check("one hard conflict", len(report["hard_conflict_relations"]) == 1)
    _check("conflict count summary", report["summary"]["relations_conflict"] == 1)
    c = report["hard_conflict_relations"][0]
    _check("conflict pair", (c["ancestor"], c["node"]) == ("app@1", "lib@1"))
    _check("avoids hard conflicts false", report["summary"]["avoids_hard_conflicts"] is False)
    _check("all compatible false", report["summary"]["all_relations_compatible"] is False)


def test_conflict_minimizing_assignment() -> None:
    # 两候选包 x(Apache-2.0 OR MIT) 与 y(Apache-2.0 OR GPL-2.0) 都被 GPL-2.0 祖先约束：
    # app(GPL-2.0) -> x, app(GPL-2.0) -> y, x -> y。
    # x 选 MIT、y 选 GPL-2.0 时：app->x ok（GPL2 吸纳 MIT），app->y ok（同证），x->y ok（MIT 容纳）=> 可行。
    # 验证搜索确实在多变量耦合下找到全局方案，而非贪心卡在首个冲突。
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": "GPL-2.0", "dependencies": ["x@1", "y@1"]},
        {"name": "x", "version": "1", "license": ["Apache-2.0", "MIT"], "dependencies": ["y@1"]},
        {"name": "y", "version": "1", "license": ["Apache-2.0", "GPL-2.0"]},
    ]))
    report = gs.select_graph_licenses(result)
    _check("global solution feasible", report["status"] == gs.FEASIBLE, report["conclusion"])
    sel = _sel_map(report)
    _check("x MIT y GPL-2.0", sel["x@1"] == "MIT" and sel["y@1"] == "GPL-2.0", str(sel))


def test_unknown_license_marks_undetermined() -> None:
    # app(MIT) -> lib(OFL-1.1 未知)，且 app -> ghost（未解析）
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": "MIT", "dependencies": ["lib@1", "ghost@1"]},
        {"name": "lib", "version": "1", "license": "OFL-1.1"},
    ]))
    report = gs.select_graph_licenses(result)
    _check("status undetermined", report["status"] == gs.UNDETERMINED, report["conclusion"])
    _check("known subgraph feasible", report["judged_outcome"] == gs.FEASIBLE)
    _check("not claiming feasible", report["summary"]["all_relations_compatible"] is False)
    _check("not fully determined", report["summary"]["fully_determined"] is False)
    _check("unknown package count", report["summary"]["unknown_license_packages"] == 1)
    _check("unresolved count", report["summary"]["unresolved_dependencies"] == 1)
    lib = [s for s in report["selections"] if s["node"]["id"] == "lib@1"][0]
    _check("lib selection undetermined", lib["status"] == gs.SEL_UNKNOWN and lib["selected_token"] is None)
    app = [s for s in report["selections"] if s["node"]["id"] == "app@1"][0]
    _check("app still selected", app["status"] == gs.SEL_SELECTED and app["selected_token"] == "MIT")
    kinds = {r["kind"] for r in report["undetermined_relations"]}
    _check("two undetermined kinds", kinds == {"unknown-license-relation", "unresolved-dependency"}, str(kinds))
    _check("unknown relation listed", len(report["unresolved_dependencies"]) == 1)
    _check("conclusion says undetermined", "未判定" in report["conclusion"])


def test_unknown_but_known_subgraph_unsolvable() -> None:
    # 已知部分本身无解，未知包不影响无解结论：整体仍为 unsolvable。
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": "GPL-2.0", "dependencies": ["lib@1", "unk@1"]},
        {"name": "lib", "version": "1", "license": ["Apache-2.0", "GPL-3.0"]},
        {"name": "unk", "version": "1", "license": "Weird-1.0"},
    ]))
    report = gs.select_graph_licenses(result)
    _check("unsolvable despite unknown", report["status"] == gs.UNSOLVABLE, report["conclusion"])
    _check("hard conflict retained", report["summary"]["relations_conflict"] == 1)
    _check("undetermined still listed", report["summary"]["relations_undetermined"] >= 1)
    unk = [s for s in report["selections"] if s["node"]["id"] == "unk@1"][0]
    _check("unk remains undetermined", unk["status"] == gs.SEL_UNKNOWN)


def test_deterministic_across_runs() -> None:
    result = analyzer.analyze_manifest(_manifest([
        {"name": "app", "version": "1", "license": ["MIT", "GPL-3.0"], "dependencies": ["a@1", "b@1"]},
        {"name": "a", "version": "1", "license": ["MIT", "Apache-2.0"]},
        {"name": "b", "version": "1", "license": ["ISC", "MIT"], "dependencies": ["a@1"]},
    ]))
    r1 = gs.select_graph_licenses(result)
    r2 = gs.select_graph_licenses(result)
    _check("same selections", _sel_map(r1) == _sel_map(r2))
    _check("same status", r1["status"] == r2["status"])
    _check("same search nodes", r1["summary"]["search_nodes"] == r2["summary"]["search_nodes"])


def test_empty_audit() -> None:
    result = analyzer.analyze_manifest({"name": "empty"})
    report = gs.select_graph_licenses(result)
    _check("empty feasible", report["status"] == gs.FEASIBLE)
    _check("zero totals", report["summary"]["relations_total"] == 0
           and report["summary"]["packages"] == 0)


def test_cyclonedx_supported() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "app", "name": "app", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}, {"license": {"id": "GPL-3.0"}}]},
            {"bom-ref": "lib", "name": "lib", "version": "1",
             "licenses": [{"expression": "GPL-2.0 OR MIT"}]},
            {"bom-ref": "deep", "name": "deep", "version": "1",
             "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": ["lib"]},
            {"ref": "lib", "dependsOn": ["deep"]},
        ],
    }
    result = cyclonedx.analyze_bom(bom)
    report = gs.select_graph_licenses(result)
    # lib 必须选 MIT（GPL-2.0 -> Apache-2.0 硬冲突；MIT 全链路兼容）
    _check("cyclonedx feasible", report["status"] == gs.FEASIBLE, report["conclusion"])
    _check("cyclonedx lib MIT", _sel_map(report)["lib@1"] == "MIT", str(_sel_map(report)))
    _check("cyclonedx source_format kept", report["audit"]["source_format"] == "cyclonedx")


def test_input_not_mutated_and_read_only() -> None:
    manifest = _manifest([
        {"name": "app", "version": "1", "license": "Proprietary", "dependencies": ["lib@1"]},
        {"name": "lib", "version": "1", "license": ["MPL-2.0", "GPL-2.0"]},
    ])
    result = analyzer.analyze_manifest(manifest)
    audit_id = database.save_audit(result, manifest)
    stored = database.get_audit(audit_id)
    conflict = stored["conflicts"][0]
    database.save_review(
        fingerprint=reviews.fingerprint_for_conflict(stored, conflict),
        ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="Proprietary", node_license="MPL-2.0 OR GPL-2.0",
        note="全图选定不应改动我",
    )
    snapshot = copy.deepcopy(stored)
    audits_before = database.list_audits(limit=500)
    reviews_before = database.list_reviews(limit=500)

    report = gs.select_graph_licenses(stored)
    _check("report produced", report["status"] in {gs.FEASIBLE, gs.MANUAL_REVIEW, gs.UNSOLVABLE, gs.UNDETERMINED})
    _check("input result not mutated", stored == snapshot)
    _check("no new audit created", database.list_audits(limit=500) == audits_before)
    _check("stored audit unchanged", database.get_audit(audit_id) == snapshot)
    _check("reviews untouched", database.list_reviews(limit=500) == reviews_before)


def main() -> None:
    test_report_envelope()
    test_or_choice_picks_compatible()
    test_transitive_all_reachable_relations()
    test_manual_review_warning_only()
    test_unsolvable_hard_conflict_unavoidable()
    test_conflict_minimizing_assignment()
    test_unknown_license_marks_undetermined()
    test_unknown_but_known_subgraph_unsolvable()
    test_deterministic_across_runs()
    test_empty_audit()
    test_cyclonedx_supported()
    test_input_not_mutated_and_read_only()
    print("\nall graphselect tests passed.")


if __name__ == "__main__":
    main()
