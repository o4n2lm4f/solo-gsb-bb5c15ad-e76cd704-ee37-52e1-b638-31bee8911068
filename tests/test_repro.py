"""审计复现包导出/核验的自测（无测试框架依赖）：python -m tests.test_repro

使用独立临时 SQLite 库，不触碰 ./data；只依赖 analyzer/database/repro/reviews，
无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, database, repro, reviews

# 隔离的临时数据库（database.connect 在调用时读取 DB_PATH，运行时替换即可）
_TMP_DIR = tempfile.mkdtemp(prefix="repro-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _conflict_manifest():
    return {
        "name": "repro-demo",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-3.0",
             "dependencies": ["lib@1", "util@2"]},
            {"name": "lib", "version": "1", "license": "Proprietary"},
            {"name": "util", "version": "2", "license": "MIT",
             "dependencies": ["lib@1"]},
        ],
    }


def _save_audit(manifest=None) -> dict:
    manifest = manifest if manifest is not None else _conflict_manifest()
    result = analyzer.analyze_manifest(manifest)
    audit_id = database.save_audit(result, manifest)
    result["audit_id"] = audit_id
    return result


def _export_bundle(audit_id: int) -> dict:
    raw = database.get_audit_raw(audit_id)
    _check("raw audit fetched", raw is not None)
    return repro.build_bundle(audit_id, raw["name"], raw["manifest"], raw["result"])


def test_canonical_and_digest() -> None:
    a = {"b": 1, "a": {"y": [1, 2], "x": "中文"}}
    b = {"a": {"x": "中文", "y": [1, 2]}, "b": 1}
    _check("canonical json key order stable", repro.canonical_json(a) == repro.canonical_json(b))
    _check(
        "canonical json compact",
        repro.canonical_json({"a": 1}) == '{"a":1}',
        repro.canonical_json({"a": 1}),
    )
    digest = repro.sha256_hex(a)
    _check("sha256 hex form", len(digest) == 64 and all(c in "0123456789abcdef" for c in digest))
    _check("digest key order insensitive", repro.sha256_hex(b) == digest)
    _check("digest value sensitive", repro.sha256_hex({"a": 2}) != repro.sha256_hex({"a": 1}))


def test_export_roundtrip_passes() -> None:
    saved = _save_audit()
    bundle = _export_bundle(saved["audit_id"])
    _check("bundle format", bundle["format"] == repro.FORMAT)
    _check("bundle name", bundle["name"] == "repro-demo")
    _check("bundle carries audit id", bundle["audit_id"] == saved["audit_id"])
    _check("bundle has both digests",
           set(bundle["digests"]) == {"manifest_sha256", "result_sha256"})
    # 摘要覆盖的是含运行元数据（audit_id/created_at）的完整保存结果
    _check("stored result keeps audit_id", "audit_id" in bundle["result"])
    _check("stored result keeps created_at", "created_at" in bundle["result"])
    _check(
        "manifest digest matches recompute",
        bundle["digests"]["manifest_sha256"] == repro.sha256_hex(bundle["manifest"]),
    )
    _check(
        "result digest matches recompute",
        bundle["digests"]["result_sha256"] == repro.sha256_hex(bundle["result"]),
    )

    report = repro.verify_bundle(bundle)
    _check("verify read only", report["read_only"] is True)
    _check("verify ok", report["ok"] is True, str(report.get("first_mismatch")))
    _check("all checks ok", all(c["ok"] for c in report["checks"]), str(report["checks"]))
    _check("no first mismatch", report["first_mismatch"] is None)
    _check("recomputed conflicts counted",
           report["recomputed"]["conflicts"] == saved["summary"]["conflicts"])
    _check("pass message mentions counts", "逐项相同" in report["message"])


def test_review_marks_do_not_affect_bundle() -> None:
    saved = _save_audit()
    conflict = saved["conflicts"][0]
    # 打一条实时复核标记（只影响 API 响应层，不落库到审计 JSON）
    database.save_review(
        fingerprint=reviews.fingerprint_for_conflict(saved, conflict),
        ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-3.0", node_license="Proprietary", note="复现包不应携带",
    )
    bundle = _export_bundle(saved["audit_id"])
    _check(
        "bundle result has no review field",
        all("review" not in c for c in bundle["result"]["conflicts"]),
    )
    _check("bundle summary has no review", "review" not in bundle["result"]["summary"])
    report = repro.verify_bundle(bundle)
    _check("verify still ok after marking", report["ok"] is True, str(report.get("first_mismatch")))


def test_tampered_manifest_digest_fails() -> None:
    saved = _save_audit()
    bundle = _export_bundle(saved["audit_id"])
    bundle["manifest"]["packages"][1]["license"] = "MIT"  # 篡改包内 manifest
    report = repro.verify_bundle(bundle)
    _check("tampered manifest not ok", report["ok"] is False)
    checks = {c["id"]: c for c in report["checks"]}
    _check("manifest digest check fails", checks["manifest_digest"]["ok"] is False)
    _check("result digest check still ok", checks["result_digest"]["ok"] is True)
    mismatch = report["first_mismatch"]
    _check("first mismatch is manifest digest", mismatch["check"] == "manifest_digest")
    _check("mismatch field", mismatch["field"] == "digests.manifest_sha256")
    _check("mismatch message mentions digest", "摘要" in mismatch["message"])


def test_tampered_result_digest_fails() -> None:
    saved = _save_audit()
    bundle = _export_bundle(saved["audit_id"])
    bundle["result"]["conflicts"][0]["severity"] = "warning"  # 篡改保存结果
    report = repro.verify_bundle(bundle)
    _check("tampered result not ok", report["ok"] is False)
    checks = {c["id"]: c for c in report["checks"]}
    _check("result digest check fails", checks["result_digest"]["ok"] is False)
    _check("first mismatch is result digest", report["first_mismatch"]["check"] == "result_digest")


def test_recompute_reports_first_field() -> None:
    saved = _save_audit()
    bundle = _export_bundle(saved["audit_id"])
    # 篡改保存结果并同步修正摘要（绕过完整性检查），专测复算比对的字段定位
    bundle["result"]["conflicts"][0]["severity"] = "warning"
    bundle["digests"]["result_sha256"] = repro.sha256_hex(bundle["result"])
    report = repro.verify_bundle(bundle)
    _check("digests pass after re-sign", all(
        c["ok"] for c in report["checks"] if c["id"] != "recompute"))
    _check("recompute check fails", report["ok"] is False)
    mismatch = report["first_mismatch"]
    _check("first mismatch is recompute", mismatch["check"] == "recompute")
    _check("first mismatch field is severity",
           mismatch["field"] == "conflicts[0].severity", str(mismatch))
    _check("mismatch carries both values",
           mismatch["stored"] == "warning" and mismatch["recomputed"] == "error")
    _check("message points at field", "conflicts[0].severity" in report["message"])

    # 路径篡改：首个不一致字段应定位到 conflicts[0].path
    bundle2 = _export_bundle(saved["audit_id"])
    bundle2["result"]["conflicts"][0]["path"] = ["app@1", "lib@1", "extra@9"]
    bundle2["digests"]["result_sha256"] = repro.sha256_hex(bundle2["result"])
    report2 = repro.verify_bundle(bundle2)
    _check("path tamper not ok", report2["ok"] is False)
    _check("path mismatch field",
           report2["first_mismatch"]["field"].startswith("conflicts[0].path"),
           str(report2["first_mismatch"]))

    # 节点许可证篡改：定位到 nodes 下具体字段
    bundle3 = _export_bundle(saved["audit_id"])
    node = next(n for n in bundle3["result"]["nodes"] if n["id"] == "lib@1")
    node["license"] = "MIT"
    bundle3["digests"]["result_sha256"] = repro.sha256_hex(bundle3["result"])
    report3 = repro.verify_bundle(bundle3)
    _check("node license tamper not ok", report3["ok"] is False)
    _check("node mismatch field",
           report3["first_mismatch"]["field"].startswith("nodes["),
           str(report3["first_mismatch"]))


def test_runtime_metadata_stripped() -> None:
    saved = _save_audit()
    bundle = _export_bundle(saved["audit_id"])
    stripped = repro.strip_runtime(bundle["result"])
    _check("audit_id stripped", "audit_id" not in stripped)
    _check("created_at stripped", "created_at" not in stripped)
    # 即便结果里混入复核标记/筛选字段，剔除后仍与复算结果一致
    dirty = copy.deepcopy(bundle["result"])
    dirty["filtered"] = True
    dirty["filter"] = "lib"
    dirty["summary"]["review"] = {"reviewed": 1, "pending": 0}
    for c in dirty["conflicts"]:
        c["review"] = {"state": "reviewed", "fingerprint": "x"}
    cleaned = repro.strip_runtime(dirty)
    _check("review stripped from conflicts",
           all("review" not in c for c in cleaned["conflicts"]))
    _check("review stripped from summary", "review" not in cleaned["summary"])
    _check("filter fields stripped", "filtered" not in cleaned and "filter" not in cleaned)
    bundle["result"] = dirty
    bundle["digests"]["result_sha256"] = repro.sha256_hex(dirty)
    report = repro.verify_bundle(bundle)
    _check("verify ok despite runtime noise", report["ok"] is True,
           str(report.get("first_mismatch")))


def test_format_errors() -> None:
    saved = _save_audit()
    good = _export_bundle(saved["audit_id"])

    def _expect_format_error(name, bundle, needle):
        try:
            repro.verify_bundle(bundle)
        except repro.BundleFormatError as exc:
            _check(name, needle in str(exc), str(exc))
            return
        raise AssertionError("%s: BundleFormatError not raised" % name)

    _expect_format_error("non dict rejected", [1, 2], "JSON 对象")
    bad_format = copy.deepcopy(good)
    bad_format["format"] = "audit-repro/v99"
    _expect_format_error("unknown format rejected", bad_format, "audit-repro/v1")
    missing_format = copy.deepcopy(good)
    del missing_format["format"]
    _expect_format_error("missing format rejected", missing_format, "audit-repro/v1")
    no_name = copy.deepcopy(good)
    no_name["name"] = ""
    _expect_format_error("empty name rejected", no_name, "name")
    no_digests = copy.deepcopy(good)
    del no_digests["digests"]
    _expect_format_error("missing digests rejected", no_digests, "digests")
    bad_digest = copy.deepcopy(good)
    bad_digest["digests"]["manifest_sha256"] = "xyz"
    _expect_format_error("malformed digest rejected", bad_digest, "manifest_sha256")
    no_manifest = copy.deepcopy(good)
    del no_manifest["manifest"]
    _expect_format_error("missing manifest rejected", no_manifest, "manifest")
    no_result = copy.deepcopy(good)
    del no_result["result"]
    _expect_format_error("missing result rejected", no_result, "result")
    bad_result = copy.deepcopy(good)
    bad_result["result"] = "not-an-object"
    _expect_format_error("non dict result rejected", bad_result, "result")


def test_unanalyzable_manifest_fails_recompute() -> None:
    saved = _save_audit()
    bundle = _export_bundle(saved["audit_id"])
    # 把 manifest 换成无法解析的内容并重新签名（结构合法但内容不可复算）
    bundle["manifest"] = {"packages": "not-a-list", "dependencies": 42}
    bundle["digests"]["manifest_sha256"] = repro.sha256_hex(bundle["manifest"])
    report = repro.verify_bundle(bundle)
    _check("unanalyzable manifest not ok", report["ok"] is False)
    checks = {c["id"]: c for c in report["checks"]}
    _check("recompute check failed", checks["recompute"]["ok"] is False)
    _check("first mismatch is recompute", report["first_mismatch"]["check"] == "recompute")


def test_cyclonedx_roundtrip() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"bom-ref": "pkg:app/shop@1.0", "name": "shop", "version": "1.0",
             "licenses": [{"license": {"id": "GPL-2.0"}}]},
            {"bom-ref": "pkg:npm/ui@2.0", "name": "ui", "version": "2.0",
             "licenses": [{"expression": "Apache-2.0"}]},
        ],
        "dependencies": [
            {"ref": "pkg:app/shop@1.0", "dependsOn": ["pkg:npm/ui@2.0"]}
        ],
    }
    saved = _save_audit(bom)
    _check("cyclonedx source format", saved.get("source_format") == "cyclonedx")
    bundle = _export_bundle(saved["audit_id"])
    report = repro.verify_bundle(bundle)
    _check("cyclonedx bundle verify ok", report["ok"] is True,
           str(report.get("first_mismatch")))


def main() -> None:
    test_canonical_and_digest()
    test_export_roundtrip_passes()
    test_review_marks_do_not_affect_bundle()
    test_tampered_manifest_digest_fails()
    test_tampered_result_digest_fails()
    test_recompute_reports_first_field()
    test_runtime_metadata_stripped()
    test_format_errors()
    test_unanalyzable_manifest_fails_recompute()
    test_cyclonedx_roundtrip()
    print("\nall repro tests passed.")


if __name__ == "__main__":
    main()
