"""单包许可证替换预演的自测（无测试框架依赖）：python -m tests.test_relicense

使用独立临时 SQLite 库验证只读性，不触碰 ./data；
核心逻辑只依赖 analyzer/cyclonedx/compare/relicense，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, cyclonedx, database, licenses, relicense, reviews

# 隔离的临时数据库（仅用于只读性验证）
_TMP_DIR = tempfile.mkdtemp(prefix="relicense-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _demo_manifest():
    # app(GPL-2.0) -> lib(Apache-2.0) 是硬冲突（专利条款）；lib -> deep(MIT)；app -> x(MIT)。
    return {
        "name": "relicense-demo",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-2.0",
             "dependencies": ["lib@1", "x@1"]},
            {"name": "lib", "version": "1", "license": "Apache-2.0",
             "dependencies": ["deep@1"]},
            {"name": "deep", "version": "1", "license": "MIT"},
            {"name": "x", "version": "1", "license": "MIT"},
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


def test_preview_lists_packages_and_candidates() -> None:
    result = _demo_result()
    report = relicense.rehearse_relicense(result)
    _check("preview not rehearsed", report["rehearsed"] is False)
    _check("preview read only", report["read_only"] is True)
    _check("preview summary empty", report["summary"] is None)
    _check("preview comparison empty", report["comparison"] is None)
    _check(
        "preview lists all packages",
        [p["id"] for p in report["packages"]] == ["app@1", "lib@1", "deep@1", "x@1"],
        str([p["id"] for p in report["packages"]]),
    )
    lib = report["packages"][1]
    _check("package brief carries license", lib["license"] == "Apache-2.0" and lib["license_known"])
    tokens = [c["token"] for c in report["candidate_licenses"]]
    _check(
        "candidates are the built-in matrix",
        tokens == list(licenses.CATEGORIES.keys()),
        str(tokens),
    )
    labels = {c["token"]: c["category_label"] for c in report["candidate_licenses"]}
    _check("candidate carries category label", labels["GPL-3.0"] == "强 Copyleft")


def test_relicense_removes_conflict() -> None:
    result = _demo_result()
    report = relicense.rehearse_relicense(result, "lib@1", "MIT")
    _check("rehearsed flag", report["rehearsed"] is True)
    target = report["target"]
    _check("target id", target["id"] == "lib@1")
    _check("license before", target["license_before"]["token"] == "Apache-2.0")
    _check("license after", target["license_after"]["token"] == "MIT")
    _check("license after known", target["license_after"]["known"] is True)

    s = report["summary"]
    _check("conflicts 1 -> 0", (s["conflicts_before"], s["conflicts_after"]) == (1, 0), str(s))
    _check("conflicts net -1", s["conflicts_net"] == -1)
    _check("total net -1", s["total_net"] == -1)
    _check("warnings untouched", s["warnings_before"] == 0 and s["warnings_after"] == 0)

    cmp = report["comparison"]
    _check("one removed finding", len(cmp["removed"]) == 1, str(cmp["removed"]))
    _check("no added/changed", not cmp["added"] and not cmp["changed"])
    gone = cmp["removed"][0]
    _check("removed pair app->lib", (gone["ancestor"], gone["node"]) == ("app@1", "lib@1"))
    _check("removed keeps original path", gone["base"]["path"] == ["app@1", "lib@1"])
    _check("removed target side null", gone["target"] is None)
    _check("removed is error", gone["severity_base"] == "error")
    _check("rehearsal meta clean", report["rehearsal"]["status"] == "clean", str(report["rehearsal"]))


def test_relicense_adds_conflict() -> None:
    result = _demo_result()
    report = relicense.rehearse_relicense(result, "x@1", "GPL-3.0")
    s = report["summary"]
    _check("conflicts 1 -> 2", (s["conflicts_before"], s["conflicts_after"]) == (1, 2), str(s))
    _check("conflicts net +1", s["conflicts_net"] == 1)
    _check("added counted", s["added"] == 1 and s["added_errors"] == 1)

    cmp = report["comparison"]
    _check("one added finding", len(cmp["added"]) == 1)
    added = cmp["added"][0]
    _check("added pair app->x", (added["ancestor"], added["node"]) == ("app@1", "x@1"))
    _check("added base side null", added["base"] is None)
    _check("added carries rehearsal path", added["target"]["path"] == ["app@1", "x@1"])
    _check("added is error", added["severity_target"] == "error")
    # 原有的 app->lib 硬冲突不受影响，不出现在任何变化列表
    keys = {(f["ancestor"], f["node"]) for bucket in (cmp["added"], cmp["removed"], cmp["changed"])
            for f in bucket}
    _check("untouched conflict omitted", ("app@1", "lib@1") not in keys)


def test_relicense_transitive_paths_recomputed() -> None:
    # deep MIT -> Proprietary：app 经 lib 传递约束 deep（2 跳硬冲突），lib 直达 deep（告警）
    result = _demo_result()
    report = relicense.rehearse_relicense(result, "deep@1", "Proprietary")
    s = report["summary"]
    _check("one error + one warning added", s["added"] == 2 and s["added_errors"] == 1, str(s))
    _check("conflicts net +1", s["conflicts_net"] == 1)
    _check("warnings net +1", s["warnings_net"] == 1)
    _check("total net +2", s["total_net"] == 2)

    added = {(f["ancestor"], f["node"]): f for f in report["comparison"]["added"]}
    _check("added pairs", set(added) == {("app@1", "deep@1"), ("lib@1", "deep@1")}, str(set(added)))
    transitive = added[("app@1", "deep@1")]
    _check(
        "transitive shortest path recomputed",
        transitive["target"]["path"] == ["app@1", "lib@1", "deep@1"],
        str(transitive["target"]["path"]),
    )
    _check("transitive distance 2", transitive["target"]["distance"] == 2)
    _check("transitive is error", transitive["severity_target"] == "error")
    direct = added[("lib@1", "deep@1")]
    _check("direct warning", direct["severity_target"] == "warning")
    _check("direct path", direct["target"]["path"] == ["lib@1", "deep@1"])


def test_severity_flip_pairing() -> None:
    # app(GPL-3.0) -> y(OFL-1.1 未知) 原为告警；y 换成 Proprietary 后同一对变为硬冲突
    result = analyzer.analyze_manifest({
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-3.0", "dependencies": ["y@1"]},
            {"name": "y", "version": "1", "license": "OFL-1.1"},
        ],
    })
    _check("originally a warning", result["summary"]["license_warnings"] == 1, str(result["summary"]))
    report = relicense.rehearse_relicense(result, "y@1", "Proprietary")
    s = report["summary"]
    _check("no added/removed", s["added"] == 0 and s["removed"] == 0, str(s))
    _check("one changed pair", s["changed"] == 1)
    _check("severity flip counted", s["severity_changed"] == 1)
    _check("conflicts net +1", s["conflicts_net"] == 1)
    _check("warnings net -1", s["warnings_net"] == -1)
    _check("total net 0", s["total_net"] == 0)

    finding = report["comparison"]["changed"][0]
    _check("changed pair app->y", (finding["ancestor"], finding["node"]) == ("app@1", "y@1"))
    _check("severity warning->error",
           finding["severity_base"] == "warning" and finding["severity_target"] == "error")
    _check("severity flagged", "severity" in finding["fields_changed"])
    _check("node license flagged", "node_license" in finding["fields_changed"])
    _check(
        "both sides carry paths",
        finding["base"]["path"] == ["app@1", "y@1"] and finding["target"]["path"] == ["app@1", "y@1"],
    )


def test_package_resolution() -> None:
    result = _demo_result()
    # 包名唯一时可直接给包名（大小写不敏感）
    report = relicense.rehearse_relicense(result, "LIB", "MIT")
    _check("bare name resolved case-insensitively", report["target"]["id"] == "lib@1")
    # id 大小写不敏感
    report = relicense.rehearse_relicense(result, "Lib@1", "MIT")
    _check("id matched case-insensitively", report["target"]["id"] == "lib@1")
    # 候选许可证别名自动规范化
    report = relicense.rehearse_relicense(result, "lib@1", "apache 2")
    _check("alias normalized", report["target"]["license_after"]["token"] == "Apache-2.0")

    multi = analyzer.analyze_manifest({
        "packages": [
            {"name": "app", "version": "1", "license": "MIT", "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "MIT"},
            {"name": "lib", "version": "2", "license": "GPL-3.0"},
        ],
    })
    _expect_error(
        "ambiguous bare name rejected",
        lambda: relicense.rehearse_relicense(multi, "lib", "MIT"),
        "对应多个版本",
    )


def test_validation_errors() -> None:
    result = _demo_result()
    _expect_error(
        "unknown package rejected",
        lambda: relicense.rehearse_relicense(result, "ghost@9", "MIT"),
        "审计中不存在包：ghost@9",
    )
    _expect_error(
        "unknown candidate rejected",
        lambda: relicense.rehearse_relicense(result, "lib@1", "OFL-1.1"),
        "不在内置兼容矩阵中",
    )
    _expect_error(
        "package without license rejected",
        lambda: relicense.rehearse_relicense(result, "lib@1"),
        "必须同时提供",
    )
    _expect_error(
        "license without package rejected",
        lambda: relicense.rehearse_relicense(result, license="MIT"),
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
        "dependencies": [{"ref": "app", "dependsOn": ["lib"]}],
    }
    result = cyclonedx.analyze_bom(bom)
    _check("cyclonedx audit conflict", result["summary"]["conflicts"] == 1, str(result["summary"]))
    report = relicense.rehearse_relicense(result, "lib@1", "MIT")
    _check("cyclonedx rehearsed", report["rehearsed"] is True)
    _check("cyclonedx conflict removed", report["summary"]["conflicts_net"] == -1)
    gone = report["comparison"]["removed"]
    _check("cyclonedx removed pair",
          [(g["ancestor"], g["node"]) for g in gone] == [("app@1", "lib@1")])
    _check("cyclonedx source_format kept",
           report["rehearsal"]["source_format"] == "cyclonedx", str(report["rehearsal"]))


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
    report = relicense.rehearse_relicense(stored_before, "lib@1", "MIT")
    _check("report produced", report["rehearsed"] is True)
    _check("input result not mutated", stored_before == snapshot)
    _check("no new audit created", database.list_audits(limit=500) == audits_before)
    _check("stored audit unchanged", database.get_audit(audit_id) == snapshot)
    _check("reviews untouched", database.list_reviews(limit=500) == reviews_before)
    _check("missing audit stays missing", database.get_audit(999999) is None)


def main() -> None:
    test_preview_lists_packages_and_candidates()
    test_relicense_removes_conflict()
    test_relicense_adds_conflict()
    test_relicense_transitive_paths_recomputed()
    test_severity_flip_pairing()
    test_package_resolution()
    test_validation_errors()
    test_cyclonedx_audit_supported()
    test_rehearsal_is_read_only()
    print("\nall relicense tests passed.")


if __name__ == "__main__":
    main()
