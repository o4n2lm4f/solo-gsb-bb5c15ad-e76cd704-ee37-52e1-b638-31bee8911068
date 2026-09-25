"""根包退役预演的自测（无测试框架依赖）：python -m tests.test_retire

使用独立临时 SQLite 库验证只读性，不触碰 ./data；
核心逻辑只依赖 analyzer/cyclonedx/retire，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, cyclonedx, database, retire

# 隔离的临时数据库（仅用于只读性验证）
_TMP_DIR = tempfile.mkdtemp(prefix="retire-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _demo_manifest():
    # 根包：root-a（GPL-3.0）、root-b（MIT）；其余节点均有入边。
    # root-a 独占 only-a、y；shared-lib/deep 被两个根包共用；
    # x、n 同时被 root-a（经 y）与 root-b（经 a2 / 直达）可达。
    return {
        "name": "retire-demo",
        "packages": [
            {"name": "root-a", "version": "1", "license": "GPL-3.0",
             "dependencies": ["shared-lib@1", "only-a@1", "y@1"]},
            {"name": "root-b", "version": "1", "license": "MIT",
             "dependencies": ["shared-lib@1", "b-only@1", "a2@1", "n@1"]},
            {"name": "shared-lib", "version": "1", "license": "MIT",
             "dependencies": ["deep@1"]},
            {"name": "deep", "version": "1", "license": "Apache-2.0"},
            {"name": "only-a", "version": "1", "license": "Proprietary"},
            {"name": "b-only", "version": "1", "license": "MIT"},
            {"name": "y", "version": "1", "license": "MIT",
             "dependencies": ["x@1"]},
            {"name": "x", "version": "1", "license": "MIT",
             "dependencies": ["n@1"]},
            {"name": "a2", "version": "1", "license": "GPL-3.0",
             "dependencies": ["x@1"]},
            {"name": "n", "version": "1", "license": "Proprietary"},
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


def test_find_roots() -> None:
    result = _demo_result()
    _check(
        "roots are packages without incoming edges",
        retire.find_roots(result) == ["root-a@1", "root-b@1"],
        str(retire.find_roots(result)),
    )
    # 纯环图没有根包
    cyclic = analyzer.analyze_manifest(
        {"packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT", "dependencies": ["a@1"]},
        ]}
    )
    _check("pure cycle has no roots", retire.find_roots(cyclic) == [])


def test_preview_lists_roots_only() -> None:
    result = _demo_result()
    report = retire.rehearse_retirement(result, [])
    _check("preview not rehearsed", report["rehearsed"] is False)
    _check("preview read only", report["read_only"] is True)
    _check("preview summary empty", report["summary"] is None)
    _check("preview lists all roots", [r["id"] for r in report["roots"]] == ["root-a@1", "root-b@1"])
    root_a = report["roots"][0]
    _check("root reachable count", root_a["reachable"] == 7, str(root_a))
    _check("root carries license", root_a["license_display"] == "GPL-3.0")
    _check("preview root not retired", all(not r["retired"] for r in report["roots"]))
    _check("preview no lost/shared", report["lost"] == [] and report["shared"] == [])


def test_retire_one_root() -> None:
    result = _demo_result()
    report = retire.rehearse_retirement(result, ["root-a@1"])
    _check("rehearsed flag", report["rehearsed"] is True)
    _check("retired echoed", report["retired"] == ["root-a@1"])
    _check("remaining roots", report["remaining_roots"] == ["root-b@1"])
    _check("root marked retired in list",
           {r["id"]: r["retired"] for r in report["roots"]} == {"root-a@1": True, "root-b@1": False})

    summary = report["summary"]
    _check("reachable before", summary["reachable_before"] == 10, str(summary))
    _check("reachable after", summary["reachable_after"] == 7, str(summary))

    lost = {n["id"]: n for n in report["lost"]}
    _check("lost packages", set(lost) == {"root-a@1", "only-a@1", "y@1"}, str(set(lost)))
    _check("retired root flagged", lost["root-a@1"]["retired_root"] is True)
    _check("transitive loss not root", lost["only-a@1"]["retired_root"] is False)

    shared = {n["id"]: n for n in report["shared"]}
    # x、n 同时被 root-a（经 y）与 root-b（经 a2 / 直达）可达，退役 root-a 后仍共用
    _check(
        "shared packages",
        set(shared) == {"shared-lib@1", "deep@1", "x@1", "n@1"},
        str(set(shared)),
    )
    _check("shared reached_by remaining root",
           shared["shared-lib@1"]["reached_by"] == ["root-b@1"], str(shared["shared-lib@1"]))
    _check("x reached_by root-b", shared["x@1"]["reached_by"] == ["root-b@1"])

    gone = {(c["ancestor"], c["node"]): c for c in report["disappearing_conflicts"]}
    _check(
        "disappearing conflicts",
        set(gone) == {("root-a@1", "only-a@1"), ("root-a@1", "n@1"), ("y@1", "n@1")},
        str(set(gone)),
    )
    _check("disappearing errors counted", summary["disappearing_errors"] == 2, str(summary))
    _check("disappearing warnings counted", summary["disappearing_warnings"] == 1)
    # 消失的冲突附原最短路径：root-a 经 y、x 到 n（3 跳）
    _check(
        "original shortest path kept",
        gone[("root-a@1", "n@1")]["path"] == ["root-a@1", "y@1", "x@1", "n@1"],
        str(gone[("root-a@1", "n@1")]["path"]),
    )
    _check("original distance kept", gone[("root-a@1", "n@1")]["distance"] == 3)
    # 仍可达的祖先/节点的冲突不消失：a2 经 x 到 n 的硬冲突保留
    _check("reachable conflict kept", ("a2@1", "n@1") not in gone)


def test_retire_other_root_shared_widens() -> None:
    result = _demo_result()
    report = retire.rehearse_retirement(result, ["root-b@1"])
    lost = {n["id"] for n in report["lost"]}
    _check("lost when retiring root-b", lost == {"root-b@1", "b-only@1", "a2@1"}, str(lost))
    shared = {n["id"]: n for n in report["shared"]}
    # x、n 也被 root-b 可达，退役 root-b 后仍由 root-a 可达
    _check(
        "shared includes x and n",
        set(shared) == {"shared-lib@1", "deep@1", "x@1", "n@1"},
        str(set(shared)),
    )
    _check("n reached_by root-a", shared["n@1"]["reached_by"] == ["root-a@1"])
    gone = {(c["ancestor"], c["node"]) for c in report["disappearing_conflicts"]}
    _check(
        "disappearing when retiring root-b",
        gone == {("a2@1", "n@1"), ("root-b@1", "n@1")},
        str(gone),
    )


def test_retire_multiple_roots() -> None:
    # 再加一个根包，退役其中两个
    manifest = _demo_manifest()
    manifest["packages"].append(
        {"name": "root-c", "version": "1", "license": "MIT", "dependencies": ["n@1"]}
    )
    result = analyzer.analyze_manifest(manifest)
    _check("three roots", retire.find_roots(result) == ["root-a@1", "root-b@1", "root-c@1"])
    report = retire.rehearse_retirement(result, ["root-a@1", "root-b@1"])
    _check("two retired", report["summary"]["retired"] == 2)
    _check("remaining root-c", report["remaining_roots"] == ["root-c@1"])
    lost = {n["id"] for n in report["lost"]}
    _check(
        "lost after retiring two roots",
        lost == {"root-a@1", "root-b@1", "only-a@1", "y@1", "b-only@1", "a2@1",
                 "shared-lib@1", "deep@1", "x@1"},
        str(lost),
    )
    # n 仍被 root-c 可达，且原本也被退役根包可达 -> shared
    shared = {n["id"]: n for n in report["shared"]}
    _check("n still shared via root-c", set(shared) == {"n@1"}, str(set(shared)))
    _check("n reached_by root-c", shared["n@1"]["reached_by"] == ["root-c@1"])
    # x -> n 的告警随 x 失联而消失
    gone = {(c["ancestor"], c["node"]) for c in report["disappearing_conflicts"]}
    _check("x->n warning disappears", ("x@1", "n@1") in gone, str(gone))


def test_validation_errors() -> None:
    result = _demo_result()
    _expect_error(
        "duplicate selection rejected",
        lambda: retire.rehearse_retirement(result, ["root-a@1", "root-a@1"]),
        "重复选择退役根包：root-a@1",
    )
    _expect_error(
        "unknown package rejected",
        lambda: retire.rehearse_retirement(result, ["ghost@9"]),
        "审计中不存在以下包：ghost@9",
    )
    _expect_error(
        "non-root package rejected",
        lambda: retire.rehearse_retirement(result, ["shared-lib@1"]),
        "以下包不是根包",
    )
    _expect_error(
        "retiring all roots rejected",
        lambda: retire.rehearse_retirement(result, ["root-a@1", "root-b@1"]),
        "不能退役全部根包（共 2 个）",
    )
    # 校验优先级：重复先于其他错误
    _expect_error(
        "duplicate checked first",
        lambda: retire.rehearse_retirement(result, ["ghost@9", "ghost@9"]),
        "重复选择",
    )


def test_cyclonedx_audit_supported() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "app", "name": "app", "version": "1",
             "licenses": [{"license": {"id": "GPL-3.0"}}]},
            {"bom-ref": "lib", "name": "lib", "version": "1",
             "licenses": [{"license": {"id": "Proprietary"}}]},
            {"bom-ref": "other", "name": "other", "version": "1",
             "licenses": [{"license": {"id": "MIT"}}]},
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": ["lib"]},
            {"ref": "other", "dependsOn": ["lib"]},
        ],
    }
    result = cyclonedx.analyze_bom(bom)
    _check("cyclonedx audit parsed", result["status"] == "conflict", result.get("error"))
    _check("cyclonedx roots", retire.find_roots(result) == ["app@1", "other@1"])

    report = retire.rehearse_retirement(result, ["app@1"])
    _check("cyclonedx lost", [n["id"] for n in report["lost"]] == ["app@1"])
    shared = report["shared"]
    _check("cyclonedx shared lib", [n["id"] for n in shared] == ["lib@1"])
    _check("cyclonedx reached_by", shared[0]["reached_by"] == ["other@1"])
    gone = report["disappearing_conflicts"]
    _check("cyclonedx conflict disappears",
           [(g["ancestor"], g["node"]) for g in gone] == [("app@1", "lib@1")])
    _check("cyclonedx original path", gone[0]["path"] == ["app@1", "lib@1"])


def test_rehearsal_is_read_only() -> None:
    manifest = _demo_manifest()
    result = analyzer.analyze_manifest(manifest)
    audit_id = database.save_audit(result, manifest)

    stored_before = database.get_audit(audit_id)
    audits_before = database.list_audits(limit=500)
    reviews_before = database.list_reviews(limit=500)

    snapshot = copy.deepcopy(stored_before)
    report = retire.rehearse_retirement(stored_before, ["root-a@1"])
    _check("report produced", report["rehearsed"] is True)
    _check("input result not mutated", stored_before == snapshot)
    _check("no new audit created", database.list_audits(limit=500) == audits_before)
    _check("stored audit unchanged", database.get_audit(audit_id) == snapshot)
    _check("reviews untouched", database.list_reviews(limit=500) == reviews_before)
    _check("missing audit stays missing", database.get_audit(999999) is None)


def main() -> None:
    test_find_roots()
    test_preview_lists_roots_only()
    test_retire_one_root()
    test_retire_other_root_shared_widens()
    test_retire_multiple_roots()
    test_validation_errors()
    test_cyclonedx_audit_supported()
    test_rehearsal_is_read_only()
    print("\nall retire tests passed.")


if __name__ == "__main__":
    main()
