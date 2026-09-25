"""跨审计复核标记的自测（无测试框架依赖）：python -m tests.test_reviews

使用独立临时 SQLite 库，不触碰 ./data；只依赖 analyzer/compare/database/reviews，
无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from app import analyzer, compare as compare_mod, database, reviews

# 隔离的临时数据库（database.connect 在调用时读取 DB_PATH，运行时替换即可）
_TMP_DIR = tempfile.mkdtemp(prefix="reviews-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _conflict_manifest(app_license: str = "GPL-3.0", lib_license: str = "Proprietary"):
    return {
        "name": "review-demo",
        "packages": [
            {"name": "app", "version": "1", "license": app_license,
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": lib_license},
        ],
    }


def _save_audit(**kwargs) -> dict:
    result = analyzer.analyze_manifest(_conflict_manifest(**kwargs))
    audit_id = database.save_audit(result, result["manifest_name"])
    result["audit_id"] = audit_id
    return result


def _only_conflict(result: dict) -> dict:
    _check("exactly one conflict", len(result["conflicts"]) == 1, str(result["conflicts"]))
    return result["conflicts"][0]


def test_fingerprint() -> None:
    fp1 = reviews.conflict_fingerprint("app@1", "lib@1", "GPL-3.0", "Proprietary")
    fp2 = reviews.conflict_fingerprint("app@1", "lib@1", "GPL-3.0", "Proprietary")
    _check("fingerprint deterministic", fp1 == fp2)
    _check("fingerprint is sha256 hex", len(fp1) == 64 and all(c in "0123456789abcdef" for c in fp1))
    _check(
        "ancestor license change alters fingerprint",
        reviews.conflict_fingerprint("app@1", "lib@1", "GPL-2.0", "Proprietary") != fp1,
    )
    _check(
        "node license change alters fingerprint",
        reviews.conflict_fingerprint("app@1", "lib@1", "GPL-3.0", "MIT") != fp1,
    )
    _check(
        "node id change alters fingerprint",
        reviews.conflict_fingerprint("app@1", "lib@2", "GPL-3.0", "Proprietary") != fp1,
    )


def test_normalize_expires_at() -> None:
    _check(
        "date only means end of day UTC",
        reviews.normalize_expires_at("2026-12-31") == "2026-12-31T23:59:59+00:00",
    )
    _check(
        "Z suffix normalized",
        reviews.normalize_expires_at("2026-12-31T10:00:00Z") == "2026-12-31T10:00:00+00:00",
    )
    _check(
        "offset converted to UTC",
        reviews.normalize_expires_at("2026-12-31T18:00:00+08:00") == "2026-12-31T10:00:00+00:00",
    )
    _check(
        "naive datetime treated as UTC",
        reviews.normalize_expires_at("2026-12-31T10:00:00") == "2026-12-31T10:00:00+00:00",
    )
    for bad in ("", "not-a-date", "2026-13-40"):
        try:
            reviews.normalize_expires_at(bad)
        except ValueError:
            continue
        raise AssertionError("invalid expires_at accepted: %r" % bad)
    print("ok - invalid expires_at rejected")


def test_mark_and_cross_audit_attach() -> None:
    first = _save_audit()
    conflict = _only_conflict(first)

    attached = reviews.attach_reviews(dict(first))
    _check("fresh audit pending", attached["conflicts"][0]["review"]["state"] == reviews.PENDING)
    _check("summary counts pending", attached["summary"]["review"] == {"reviewed": 0, "pending": 1})

    fingerprint = reviews.fingerprint_for_conflict(first, conflict)
    record = database.save_review(
        fingerprint=fingerprint,
        ancestor=conflict["ancestor"],
        node=conflict["node"],
        ancestor_license="GPL-3.0",
        node_license="Proprietary",
        note="法务已确认允许组合分发",
    )
    _check("record active", record["state"] == database.REVIEW_ACTIVE, str(record))
    _check("record keeps note", record["note"] == "法务已确认允许组合分发")
    _check("record no expiry", record["expires_at"] is None)

    attached = reviews.attach_reviews(dict(first))
    review = attached["conflicts"][0]["review"]
    _check("marked conflict reviewed", review["state"] == reviews.REVIEWED)
    _check("review carries note", review["note"] == "法务已确认允许组合分发")
    _check("review carries id", review["review_id"] == record["id"])
    _check("summary counts reviewed", attached["summary"]["review"] == {"reviewed": 1, "pending": 0})

    # 跨审计：同一依赖关系在新审计中重现，指纹一致 -> 自动带出同一标记
    second = _save_audit()
    _check("different audit id", second["audit_id"] != first["audit_id"])
    attached_second = reviews.attach_reviews(dict(second))
    _check(
        "cross-audit attach",
        attached_second["conflicts"][0]["review"]["state"] == reviews.REVIEWED,
    )
    _check(
        "cross-audit same review id",
        attached_second["conflicts"][0]["review"]["review_id"] == record["id"],
    )


def test_license_change_returns_pending() -> None:
    _save_audit()  # 确保上一条标记存在（GPL-3.0 -> Proprietary）
    changed = _save_audit(app_license="GPL-2.0")  # 祖先许可证变化 -> 指纹变化
    conflict = _only_conflict(changed)
    _check("still a hard conflict", conflict["severity"] == "error")
    attached = reviews.attach_reviews(dict(changed))
    _check(
        "license change back to pending",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )


def test_expiry_returns_pending() -> None:
    result = _save_audit()
    conflict = _only_conflict(result)
    fingerprint = reviews.fingerprint_for_conflict(result, conflict)
    record = database.save_review(
        fingerprint=fingerprint,
        ancestor=conflict["ancestor"],
        node=conflict["node"],
        ancestor_license="GPL-3.0",
        node_license="Proprietary",
        note="过期标记",
        expires_at="2020-01-01T00:00:00+00:00",
    )
    _check("stored record computed expired", record["state"] == database.REVIEW_EXPIRED)
    attached = reviews.attach_reviews(dict(result))
    _check(
        "expired mark not attached",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )
    expired = database.list_reviews(state=database.REVIEW_EXPIRED, fingerprint=fingerprint)
    _check("expired listed by state", any(r["id"] == record["id"] for r in expired))
    active = database.list_reviews(state=database.REVIEW_ACTIVE, fingerprint=fingerprint)
    _check("expired not in active list", all(r["id"] != record["id"] for r in active))


def test_revoke_returns_pending() -> None:
    result = _save_audit()
    conflict = _only_conflict(result)
    fingerprint = reviews.fingerprint_for_conflict(result, conflict)
    record = database.save_review(
        fingerprint=fingerprint,
        ancestor=conflict["ancestor"],
        node=conflict["node"],
        ancestor_license="GPL-3.0",
        node_license="Proprietary",
        note="将被撤销",
    )
    revoked = database.revoke_review(record["id"])
    _check("revoke returns record", revoked is not None and revoked["id"] == record["id"])
    _check("state revoked", revoked["state"] == database.REVIEW_REVOKED, str(revoked))
    _check("revoked_at set", bool(revoked["revoked_at"]))
    attached = reviews.attach_reviews(dict(result))
    _check(
        "revoked mark not attached",
        attached["conflicts"][0]["review"]["state"] == reviews.PENDING,
    )
    _check("revoke missing id", database.revoke_review(999999) is None)
    kept = database.get_review(record["id"])
    _check("revoked record kept", kept is not None and kept["state"] == database.REVIEW_REVOKED)


def test_latest_mark_supersedes() -> None:
    result = _save_audit()
    conflict = _only_conflict(result)
    fingerprint = reviews.fingerprint_for_conflict(result, conflict)
    first = database.save_review(
        fingerprint=fingerprint, ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-3.0", node_license="Proprietary", note="第一次复核",
    )
    second = database.save_review(
        fingerprint=fingerprint, ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-3.0", node_license="Proprietary", note="第二次复核",
    )
    _check(
        "old mark superseded",
        database.get_review(first["id"])["state"] == database.REVIEW_SUPERSEDED,
    )
    _check("new mark active", database.get_review(second["id"])["state"] == database.REVIEW_ACTIVE)
    marks = database.active_review_map([fingerprint])
    _check("only latest valid mark", marks[fingerprint]["id"] == second["id"])
    attached = reviews.attach_reviews(dict(result))
    _check("attached note is latest", attached["conflicts"][0]["review"]["note"] == "第二次复核")
    history = database.list_reviews(fingerprint=fingerprint)
    _check("history kept", len(history) >= 2, str(len(history)))


def test_stored_result_and_compare_untouched() -> None:
    base = _save_audit()
    target = _save_audit(app_license="GPL-2.0")
    # 给 base 的冲突打上标记，确认持久化内容与对比不受影响
    conflict = _only_conflict(base)
    database.save_review(
        fingerprint=reviews.fingerprint_for_conflict(base, conflict),
        ancestor=conflict["ancestor"], node=conflict["node"],
        ancestor_license="GPL-3.0", node_license="Proprietary", note="不应影响对比",
    )
    stored = database.get_audit(base["audit_id"])
    _check(
        "stored conflicts carry no review field",
        all("review" not in c for c in stored["conflicts"]),
    )
    _check("stored summary has no review key", "review" not in stored["summary"])

    diff = compare_mod.compare_audits(
        database.get_audit(base["audit_id"]), database.get_audit(target["audit_id"])
    )
    _check("compare still read only", diff["read_only"] is True)
    _check("severity flip detected", len(diff["changed"]) == 1, str(diff["changed"]))
    finding = diff["changed"][0]
    _check(
        "severity preserved on both sides",
        finding["severity_base"] == "error" and finding["severity_target"] == "error",
    )
    _check("license change flagged", "ancestor_license" in finding["fields_changed"])
    _check(
        "no review leakage into compare",
        all("review" not in (f.get("base") or {}) and "review" not in (f.get("target") or {})
            for bucket in (diff["added"], diff["removed"], diff["changed"]) for f in bucket),
    )


def main() -> None:
    test_fingerprint()
    test_normalize_expires_at()
    test_mark_and_cross_audit_attach()
    test_license_change_returns_pending()
    test_expiry_returns_pending()
    test_revoke_returns_pending()
    test_latest_mark_supersedes()
    test_stored_result_and_compare_untouched()
    print("\nall review tests passed.")


if __name__ == "__main__":
    main()
