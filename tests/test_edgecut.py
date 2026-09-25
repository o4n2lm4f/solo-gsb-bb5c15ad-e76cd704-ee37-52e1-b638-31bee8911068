"""最少断边分析的自测（无测试框架依赖）：python -m tests.test_edgecut

使用独立临时 SQLite 库验证只读性，不触碰 ./data；
核心逻辑只依赖 analyzer/edgecut，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, database, edgecut

# 隔离的临时数据库（仅用于只读性验证）
_TMP_DIR = tempfile.mkdtemp(prefix="edgecut-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _expect_error(name: str, fn, needle: str) -> None:
    try:
        fn()
    except ValueError as exc:
        _check(name, needle in str(exc), "message=%r" % str(exc))
        return
    raise AssertionError("%s 未抛出 ValueError" % name)


def _demo_manifest():
    # ancestor=anc@1（GPL-2.0）到 target=tgt@1（Apache-2.0）之间存在
    # 两条边不相交路径（经 p1/p2 与 q1/q2），另有汇合到 m 的共享尾部
    # （anc 直达 m 使 m->tgt 成为真正瓶颈前，先走双路径结构）。
    return {
        "name": "edgecut-demo",
        "packages": [
            {"name": "anc", "version": "1", "license": "GPL-2.0",
             "dependencies": ["p1@1", "q1@1", "m@1"]},
            {"name": "p1", "version": "1", "license": "MIT",
             "dependencies": ["p2@1"]},
            {"name": "p2", "version": "1", "license": "MIT",
             "dependencies": ["tgt@1"]},
            {"name": "q1", "version": "1", "license": "MIT",
             "dependencies": ["q2@1"]},
            {"name": "q2", "version": "1", "license": "MIT",
             "dependencies": ["tgt@1"]},
            {"name": "m", "version": "1", "license": "MIT",
             "dependencies": ["tgt@1"]},
            {"name": "tgt", "version": "1", "license": "Apache-2.0"},
        ],
    }


def _demo_result():
    return analyzer.analyze_manifest(_demo_manifest())


def test_parallel_paths_require_two_edges() -> None:
    # 仅双路径部分：anc -> {p1->p2, q1->q2} -> tgt，最少断边为 2
    result = analyzer.analyze_manifest({
        "name": "parallel",
        "packages": [
            {"name": "anc", "version": "1", "license": "GPL-2.0",
             "dependencies": ["p1@1", "q1@1"]},
            {"name": "p1", "version": "1", "license": "MIT",
             "dependencies": ["p2@1"]},
            {"name": "p2", "version": "1", "license": "MIT",
             "dependencies": ["tgt@1"]},
            {"name": "q1", "version": "1", "license": "MIT",
             "dependencies": ["q2@1"]},
            {"name": "q2", "version": "1", "license": "MIT",
             "dependencies": ["tgt@1"]},
            {"name": "tgt", "version": "1", "license": "Apache-2.0"},
        ],
    })
    conflict = next(c for c in result["conflicts"] if c["ancestor"] == "anc@1" and c["node"] == "tgt@1")
    _check("parallel conflict exists", conflict["id"] == "C001", conflict.get("id"))
    report = edgecut.analyze_cut(result, conflict["id"])
    _check("read only", report["read_only"] is True)
    _check("deterministic", report["deterministic"] is True)
    _check("reachable before", report["reachable_before"] is True)
    _check("min cut is 2 for two parallel paths", report["cut_count"] == 2, str(report["cut_edges"]))
    cut_ids = {(e["source"], e["target"]) for e in report["cut_edges"]}
    _check(
        "cut hits each parallel path",
        cut_ids == {("anc@1", "p1@1"), ("anc@1", "q1@1")},
        str(cut_ids),
    )
    _check("two edge-disjoint paths reported", report["edge_disjoint_paths_count"] == 2)
    _check(
        "edge-disjoint paths are anc->p and anc->q chains",
        sorted(len(p) for p in report["edge_disjoint_paths"]) == [4, 4],
        str(report["edge_disjoint_paths"]),
    )
    _check("unreachable after removal", report["reachable_after"] is False)
    _check("no residual path", report["residual_shortest_path"] == [])
    _check("verification flags", all(report["verification"].values()), str(report["verification"]))


def test_merged_tail_is_single_bottleneck() -> None:
    # 汇合路径：双路径汇入 m 后只经 m->tgt，最少断边为 1
    result = analyzer.analyze_manifest({
        "name": "merge",
        "packages": [
            {"name": "anc", "version": "1", "license": "GPL-2.0",
             "dependencies": ["p1@1", "q1@1"]},
            {"name": "p1", "version": "1", "license": "MIT",
             "dependencies": ["m@1"]},
            {"name": "q1", "version": "1", "license": "MIT",
             "dependencies": ["m@1"]},
            {"name": "m", "version": "1", "license": "MIT",
             "dependencies": ["tgt@1"]},
            {"name": "tgt", "version": "1", "license": "Apache-2.0"},
        ],
    })
    conflict = next(c for c in result["conflicts"] if c["node"] == "tgt@1" and c["ancestor"] == "anc@1")
    report = edgecut.analyze_cut(result, conflict["id"])
    _check("merged tail min cut is 1", report["cut_count"] == 1, str(report["cut_edges"]))
    _check(
        "bottleneck edge is m -> tgt",
        (report["cut_edges"][0]["source"], report["cut_edges"][0]["target"]) == ("m@1", "tgt@1"),
        str(report["cut_edges"]),
    )
    _check("one edge-disjoint path", report["edge_disjoint_paths_count"] == 1)
    _check("target unreachable after", report["reachable_after"] is False)


def test_cycle_does_not_break_cut() -> None:
    # 依赖环 a<->b，anc 有两个独立入口（->a、->b），a、b 各有一条到 tgt
    # 的出口边：存在 anc->a->tgt 与 anc->b->tgt 两条边不相交路径，最少断边为 2；
    # 环（a->b、b->a）不影响结果。
    result = analyzer.analyze_manifest({
        "name": "cycle",
        "packages": [
            {"name": "anc", "version": "1", "license": "GPL-2.0",
             "dependencies": ["a@1", "b@1"]},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["b@1", "tgt@1"]},
            {"name": "b", "version": "1", "license": "MIT",
             "dependencies": ["a@1", "tgt@1"]},
            {"name": "tgt", "version": "1", "license": "Apache-2.0"},
        ],
    })
    conflict = next(c for c in result["conflicts"] if c["node"] == "tgt@1" and c["ancestor"] == "anc@1")
    report = edgecut.analyze_cut(result, conflict["id"])
    _check("cycle graph min cut is 2", report["cut_count"] == 2, str(report["cut_edges"]))
    _check("cycle graph unreachable after", report["reachable_after"] is False)
    _check("two edge-disjoint paths despite cycle", report["edge_disjoint_paths_count"] == 2)


def test_cycle_with_single_exit_is_one() -> None:
    # 环 a<->b 只有 b->tgt 一个出口，最少断边为 1（出口边）
    result = analyzer.analyze_manifest({
        "name": "cycle-one-exit",
        "packages": [
            {"name": "anc", "version": "1", "license": "GPL-2.0",
             "dependencies": ["a@1"]},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT",
             "dependencies": ["a@1", "tgt@1"]},
            {"name": "tgt", "version": "1", "license": "Apache-2.0"},
        ],
    })
    conflict = next(c for c in result["conflicts"] if c["node"] == "tgt@1" and c["ancestor"] == "anc@1")
    report = edgecut.analyze_cut(result, conflict["id"])
    _check("single cycle exit min cut is 1", report["cut_count"] == 1, str(report["cut_edges"]))
    # 入口 anc->a 与出口 b->tgt 都是大小为 1 的合法最小割；按边声明顺序的
    # 确定性 BFS 给出的割边是入口 anc -> a。
    _check(
        "cut edge is the entrance anc -> a",
        (report["cut_edges"][0]["source"], report["cut_edges"][0]["target"]) == ("anc@1", "a@1"),
        str(report["cut_edges"]),
    )


def test_direct_conflict_single_edge() -> None:
    result = _demo_result()
    # m@1 -> tgt@1 是 1 跳直接硬冲突（m 为 MIT，无冲突）；取 anc->tgt 的 3 路径冲突
    conflict = next(
        c for c in result["conflicts"]
        if c["ancestor"] == "anc@1" and c["node"] == "tgt@1"
    )
    report = edgecut.analyze_cut(result, conflict["id"])
    # 三条边不相交路径：anc->p1->p2->tgt、anc->q1->q2->tgt、anc->m->tgt
    _check("three disjoint paths -> min cut 3", report["cut_count"] == 3, str(report["cut_edges"]))
    _check("three edge-disjoint paths", report["edge_disjoint_paths_count"] == 3)
    pairs = {(e["source"], e["target"]) for e in report["cut_edges"]}
    _check(
        "cut edges are the three outgoing edges of anc",
        pairs == {("anc@1", "p1@1"), ("anc@1", "q1@1"), ("anc@1", "m@1")},
        str(pairs),
    )
    _check("unreachable after 3 cuts", report["reachable_after"] is False)
    # 原最短路径为 anc -> m -> tgt（2 跳），割边 anc->m 在原最短路径上
    on_path = [e for e in report["cut_edges"] if e["on_original_shortest_path"]]
    _check("one cut edge on original shortest path", len(on_path) == 1, str(on_path))
    _check(
        "flagged edge is anc -> m",
        (on_path[0]["source"], on_path[0]["target"]) == ("anc@1", "m@1"),
        str(on_path),
    )
    _check(
        "report carries original shortest path",
        report["original_shortest_path"] == conflict["path"] == ["anc@1", "m@1", "tgt@1"],
        str(report["original_shortest_path"]),
    )


def test_direct_edge_conflict() -> None:
    result = analyzer.analyze_manifest({
        "name": "direct",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-2.0",
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "Apache-2.0"},
        ],
    })
    report = edgecut.analyze_cut(result, "C001")
    _check("direct conflict min cut is 1", report["cut_count"] == 1)
    _check(
        "cut edge is app -> lib",
        (report["cut_edges"][0]["source"], report["cut_edges"][0]["target"]) == ("app@1", "lib@1"),
        str(report["cut_edges"]),
    )
    _check("direct edge on shortest path", report["cut_edges"][0]["on_original_shortest_path"] is True)
    _check("direct unreachable after", report["reachable_after"] is False)


def test_deterministic_across_runs() -> None:
    result = _demo_result()
    conflict = next(
        c for c in result["conflicts"] if c["ancestor"] == "anc@1" and c["node"] == "tgt@1"
    )
    first = edgecut.analyze_cut(result, conflict["id"])
    for _ in range(3):
        again = edgecut.analyze_cut(result, conflict["id"])
        _check(
            "cut edge set stable across runs",
            [(e["source"], e["target"]) for e in again["cut_edges"]]
            == [(e["source"], e["target"]) for e in first["cut_edges"]],
        )
        _check("flow paths stable across runs", again["edge_disjoint_paths"] == first["edge_disjoint_paths"])


def test_warning_conflict_also_supported() -> None:
    # 告警级条目（severity=warning）同样可分析：MIT 祖先 + unknown 许可证后代
    result = analyzer.analyze_manifest({
        "name": "warning-case",
        "packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "OFL-1.1"},
        ],
    })
    warning = next(c for c in result["conflicts"] if c["severity"] == "warning")
    report = edgecut.analyze_cut(result, warning["id"])
    _check("warning severity preserved", report["conflict"]["severity"] == "warning")
    _check("warning min cut computed", report["cut_count"] == 1, str(report["cut_edges"]))
    _check("warning unreachable after", report["reachable_after"] is False)


def test_conflict_not_found() -> None:
    result = _demo_result()
    try:
        edgecut.analyze_cut(result, "C999")
    except edgecut.ConflictNotFound as exc:
        _check("conflict not found raises ConflictNotFound", str(exc) == "C999", str(exc))
    else:
        raise AssertionError("不存在的冲突应抛出 ConflictNotFound")
    try:
        edgecut.find_conflict(result, "  c001  ")  # 去空白但大小写敏感
    except edgecut.ConflictNotFound:
        print("ok - conflict id match is exact (case-sensitive)")
    else:
        raise AssertionError("冲突 id 应精确匹配，小写 c001 不应命中 C001")


def test_does_not_mutate_audit_or_reviews() -> None:
    result = _demo_result()
    aid = database.save_audit(result, _demo_manifest())
    stored_before = database.get_audit(aid)
    snapshot = copy.deepcopy(stored_before)
    conflict = next(
        c for c in stored_before["conflicts"]
        if c["ancestor"] == "anc@1" and c["node"] == "tgt@1"
    )
    report = edgecut.analyze_cut(stored_before, conflict["id"])
    stored_after = database.get_audit(aid)
    _check("audit json unchanged after edgecut", stored_after == snapshot)
    _check("edges untouched", stored_after["edges"] == snapshot["edges"])
    _check("conflicts untouched", stored_after["conflicts"] == snapshot["conflicts"])
    # 复核标记表不被分析触碰：给该冲突打标后再分析，标记仍然有效
    from app import reviews
    token_map = {n["id"]: n["license"] for n in stored_after["nodes"]}
    fp = reviews.conflict_fingerprint(
        conflict["ancestor"], conflict["node"],
        token_map[conflict["ancestor"]], token_map[conflict["node"]],
    )
    database.save_review(fp, conflict["ancestor"], conflict["node"],
                         token_map[conflict["ancestor"]], token_map[conflict["node"]],
                         note="法务确认")
    edgecut.analyze_cut(stored_after, conflict["id"])
    marks = database.active_review_map([fp])
    _check("review mark survives edgecut analysis", fp in marks, str(marks))


def test_cyclonedx_audit_supported() -> None:
    from app import cyclonedx
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"type": "application", "bom-ref": "pkg:a@1", "name": "a", "version": "1",
             "licenses": [{"license": {"id": "GPL-2.0"}}]},
            {"type": "library", "bom-ref": "pkg:b@1", "name": "b", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "library", "bom-ref": "pkg:c@1", "name": "c", "version": "1",
             "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ],
        "dependencies": [
            {"ref": "pkg:a@1", "dependsOn": ["pkg:b@1"]},
            {"ref": "pkg:b@1", "dependsOn": ["pkg:c@1"]},
        ],
    }
    result = cyclonedx.analyze_bom(bom, "cdx-edgecut")
    _check("cyclonedx parsed", result.get("source_format") == "cyclonedx")
    conflict = next(c for c in result["conflicts"] if c["node"] == "c@1")
    report = edgecut.analyze_cut(result, conflict["id"])
    _check("cyclonedx min cut 1", report["cut_count"] == 1, str(report["cut_edges"]))
    # a->b 与 b->c 都是大小为 1 的合法最小割；按边声明顺序确定性给出 a -> b
    _check(
        "cyclonedx cut edge",
        (report["cut_edges"][0]["source"], report["cut_edges"][0]["target"]) == ("a@1", "b@1"),
        str(report["cut_edges"]),
    )
    _check("cyclonedx unreachable after", report["reachable_after"] is False)
    _check("audit meta carries source format", report["audit"]["source_format"] == "cyclonedx")


def main() -> None:
    test_parallel_paths_require_two_edges()
    test_merged_tail_is_single_bottleneck()
    test_cycle_does_not_break_cut()
    test_cycle_with_single_exit_is_one()
    test_direct_conflict_single_edge()
    test_direct_edge_conflict()
    test_deterministic_across_runs()
    test_warning_conflict_also_supported()
    test_conflict_not_found()
    test_does_not_mutate_audit_or_reviews()
    test_cyclonedx_audit_supported()
    print("\nall edgecut tests passed.")


if __name__ == "__main__":
    main()
