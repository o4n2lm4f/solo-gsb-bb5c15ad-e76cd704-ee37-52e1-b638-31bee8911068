"""SQLite 持久层：启动时建库建表，提供审计记录的存取。"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_BASE_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = Path(os.environ.get("DATABASE_URL", str(_BASE_DIR / "audit.db")))
# 允许 DATABASE_URL=sqlite:////path 风格
if str(DB_PATH).startswith("sqlite:///"):
    DB_PATH = Path(str(DB_PATH).replace("sqlite:///", "", 1))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS manifests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    status        TEXT    NOT NULL,
    package_count INTEGER NOT NULL,
    edge_count    INTEGER NOT NULL,
    conflict_count INTEGER NOT NULL,
    warning_count INTEGER NOT NULL,
    result_json   TEXT    NOT NULL,
    manifest_json TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS conflicts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_id INTEGER NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
    conflict_uid TEXT NOT NULL,
    severity    TEXT NOT NULL,
    status      TEXT NOT NULL,
    ancestor    TEXT NOT NULL,
    node        TEXT NOT NULL,
    distance    INTEGER NOT NULL,
    path_json   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_conflicts_manifest ON conflicts(manifest_id);
CREATE INDEX IF NOT EXISTS idx_conflicts_node ON conflicts(node);
CREATE INDEX IF NOT EXISTS idx_manifests_created ON manifests(created_at);

-- 跨审计复核标记：按指纹关联冲突条目，与具体审计记录解耦（删除审计不影响标记）。
-- status: active（有效）/ superseded（被同指纹新标记取代）/ revoked（已撤销）。
-- 过期不做物理改写，读取时按 expires_at 与当前时间比较即时判定。
CREATE TABLE IF NOT EXISTS reviews (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint      TEXT NOT NULL,
    ancestor         TEXT NOT NULL,
    node             TEXT NOT NULL,
    ancestor_license TEXT NOT NULL,
    node_license     TEXT NOT NULL,
    note             TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'active',
    expires_at       TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    revoked_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_reviews_fingerprint ON reviews(fingerprint);
CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status);
"""

# 复核标记状态（存储层）
REVIEW_ACTIVE = "active"
REVIEW_SUPERSEDED = "superseded"
REVIEW_REVOKED = "revoked"
# 仅由读取时计算得出的派生状态（不落库）
REVIEW_EXPIRED = "expired"

_REVIEW_STATES = (REVIEW_ACTIVE, REVIEW_SUPERSEDED, REVIEW_REVOKED, REVIEW_EXPIRED)


def get_db_path() -> Path:
    return DB_PATH


def init_db() -> None:
    """启动时调用：确保目录与数据库文件存在并完成建表。"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def save_audit(result: Dict[str, Any], raw_manifest: Any) -> int:
    """持久化一次审计，返回自增主键。"""
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = dict(result)
    result["created_at"] = created_at
    summary = result["summary"]
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO manifests
                (name, status, package_count, edge_count, conflict_count,
                 warning_count, result_json, manifest_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["manifest_name"],
                result["status"],
                summary["packages"],
                summary["edges"],
                summary["conflicts"],
                summary["license_warnings"] + summary["warnings"],
                json.dumps(result, ensure_ascii=False),
                json.dumps(raw_manifest, ensure_ascii=False),
                created_at,
            ),
        )
        manifest_id = int(cur.lastrowid)
        # audit_id 写回结果后再持久化，保证导出 JSON 自带主键
        result["audit_id"] = manifest_id
        conn.execute(
            "UPDATE manifests SET result_json = ? WHERE id = ?",
            (json.dumps(result, ensure_ascii=False), manifest_id),
        )
        rows = [
            (
                manifest_id,
                c["id"],
                c["severity"],
                c["status"],
                c["ancestor"],
                c["node"],
                c["distance"],
                json.dumps(c["path"], ensure_ascii=False),
                c["reason"],
                created_at,
            )
            for c in result.get("conflicts", [])
        ]
        conn.executemany(
            """
            INSERT INTO conflicts
                (manifest_id, conflict_uid, severity, status, ancestor, node,
                 distance, path_json, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
    return manifest_id


def _manifest_brief(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "status": row["status"],
        "package_count": row["package_count"],
        "edge_count": row["edge_count"],
        "conflict_count": row["conflict_count"],
        "warning_count": row["warning_count"],
        "created_at": row["created_at"],
    }


def list_audits(limit: int = 20) -> List[Dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM manifests ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_manifest_brief(r) for r in rows]


def get_audit(manifest_id: int) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute(
            "SELECT result_json FROM manifests WHERE id = ?", (manifest_id,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["result_json"])


def get_audit_raw(manifest_id: int) -> Optional[Dict[str, Any]]:
    """返回审计的原始 manifest 与保存结果（未附着复核标记），用于导出复现包。"""
    with connect() as conn:
        row = conn.execute(
            "SELECT name, manifest_json, result_json FROM manifests WHERE id = ?",
            (manifest_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "name": row["name"],
        "manifest": json.loads(row["manifest_json"]),
        "result": json.loads(row["result_json"]),
    }


def audit_exists(manifest_id: int) -> bool:
    with connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM manifests WHERE id = ?", (manifest_id,)
        ).fetchone()
    return row is not None


def delete_audit(manifest_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM manifests WHERE id = ?", (manifest_id,))
        conn.commit()
        return cur.rowcount > 0


# --- 跨审计复核标记 -----------------------------------------------------------


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _review_state(status: str, expires_at: Optional[str], now: Optional[str] = None) -> str:
    """计算标记的当前有效状态：active 但已过 expires_at 的视为 expired。"""
    if status == REVIEW_ACTIVE and expires_at:
        if expires_at <= (now or utcnow()):
            return REVIEW_EXPIRED
    return status


def _review_dict(row: sqlite3.Row, now: Optional[str] = None) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "ancestor": row["ancestor"],
        "node": row["node"],
        "ancestor_license": row["ancestor_license"],
        "node_license": row["node_license"],
        "note": row["note"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "revoked_at": row["revoked_at"],
        "state": _review_state(row["status"], row["expires_at"], now),
    }


def save_review(
    fingerprint: str,
    ancestor: str,
    node: str,
    ancestor_license: str,
    node_license: str,
    note: str = "",
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """创建复核标记；同一指纹的旧有效标记自动转为 superseded（保留历史）。"""
    now = utcnow()
    with connect() as conn:
        conn.execute(
            "UPDATE reviews SET status = ?, updated_at = ? WHERE fingerprint = ? AND status = ?",
            (REVIEW_SUPERSEDED, now, fingerprint, REVIEW_ACTIVE),
        )
        cur = conn.execute(
            """
            INSERT INTO reviews
                (fingerprint, ancestor, node, ancestor_license, node_license,
                 note, status, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                ancestor,
                node,
                ancestor_license,
                node_license,
                note,
                REVIEW_ACTIVE,
                expires_at,
                now,
                now,
            ),
        )
        review_id = int(cur.lastrowid)
        conn.commit()
    record = get_review(review_id)
    assert record is not None  # 刚插入必然存在
    return record


def get_review(review_id: int) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM reviews WHERE id = ?", (review_id,)).fetchone()
    return _review_dict(row) if row is not None else None


def list_reviews(
    state: Optional[str] = None,
    fingerprint: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """按状态/指纹列出复核记录（按 id 倒序，最新在前）。

    ``state`` 可取 active / expired / revoked / superseded，缺省返回全部。
    """
    clauses: List[str] = []
    params: List[Any] = []
    if fingerprint:
        clauses.append("fingerprint = ?")
        params.append(fingerprint)
    now = utcnow()
    if state == REVIEW_ACTIVE:
        clauses.append("status = ? AND (expires_at IS NULL OR expires_at > ?)")
        params.extend([REVIEW_ACTIVE, now])
    elif state == REVIEW_EXPIRED:
        clauses.append("status = ? AND expires_at IS NOT NULL AND expires_at <= ?")
        params.extend([REVIEW_ACTIVE, now])
    elif state in (REVIEW_REVOKED, REVIEW_SUPERSEDED):
        clauses.append("status = ?")
        params.append(state)
    elif state is not None:
        raise ValueError("未知的复核标记状态：%r（可选：%s）" % (state, "、".join(_REVIEW_STATES)))
    sql = "SELECT * FROM reviews"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_review_dict(row, now) for row in rows]


def revoke_review(review_id: int) -> Optional[Dict[str, Any]]:
    """撤销复核标记（软删除，保留记录）；记录不存在时返回 None。"""
    now = utcnow()
    with connect() as conn:
        row = conn.execute(
            "SELECT status FROM reviews WHERE id = ?", (review_id,)
        ).fetchone()
        if row is None:
            return None
        if row["status"] == REVIEW_ACTIVE:
            conn.execute(
                "UPDATE reviews SET status = ?, revoked_at = ?, updated_at = ? WHERE id = ?",
                (REVIEW_REVOKED, now, now, review_id),
            )
            conn.commit()
    return get_review(review_id)


def active_review_map(fingerprints: Any) -> Dict[str, Dict[str, Any]]:
    """给定一组指纹，返回 {指纹: 当前有效标记}（未过期且未撤销）。

    同一指纹至多一条 active 记录（创建新标记时旧记录已被 superseded），
    因此查询结果即“最新有效标记”。
    """
    fps = [fp for fp in {str(f) for f in fingerprints} if fp]
    if not fps:
        return {}
    now = utcnow()
    marks: Dict[str, Dict[str, Any]] = {}
    with connect() as conn:
        # 分批避免超出 SQLite 变量上限
        for start in range(0, len(fps), 500):
            batch = fps[start : start + 500]
            placeholders = ",".join("?" for _ in batch)
            rows = conn.execute(
                "SELECT * FROM reviews WHERE status = ? AND fingerprint IN (%s) "
                "AND (expires_at IS NULL OR expires_at > ?)" % placeholders,
                [REVIEW_ACTIVE, *batch, now],
            ).fetchall()
            for row in rows:
                marks[row["fingerprint"]] = _review_dict(row, now)
    return marks
