"""审计复现包：导出与离线核验（只读）。

复现包把一次历史审计的**原始 manifest** 与**保存的审计结果**（未附着实时复核
标记）打包成一个可离线转交的 JSON 文件，结构如下（``audit-repro/v1``）::

    {
      "format": "audit-repro/v1",        # 格式版本
      "name": "<审计名称>",
      "audit_id": 3,                     # 来源审计 id（仅元信息，核验时忽略）
      "exported_at": "...",              # 导出时间（仅元信息，核验时忽略）
      "digests": {
        "manifest_sha256": "...",        # 原始 manifest 稳定序列化的 SHA-256
        "result_sha256": "..."           # 保存结果稳定序列化的 SHA-256
      },
      "manifest": {...},                 # 原始 manifest（SQLite manifest_json）
      "result": {...}                    # 保存的审计结果（SQLite result_json）
    }

核验流程（纯内存只读，不创建审计、不改动复核标记）：

1. **结构校验** —— 格式版本、必备字段与摘要形式，不符时抛出
   :class:`BundleFormatError`（API 层转为 422 并给出明确提示）；
2. **摘要重算** —— 对包内 ``manifest`` / ``result`` 按稳定键（键名排序、
   紧凑分隔符）序列化后重算 SHA-256，与包内 ``digests`` 逐项比对，
   确认文件自导出后未被改动；
3. **分析器复算** —— 用包内 ``manifest`` 重新调用现有分析器，剔除审计 ID、
   时间、复核标记等运行元数据后，与保存结果按固定顺序逐项比对
   （manifest_name → status → summary → nodes → edges → conflicts →
   unresolved → warnings → 其余字段），节点、依赖边、冲突严重程度与最短
   路径都在比对之列，发现不一致时指出**首个不一致字段**。

只有两处摘要与复算结果**全部一致**才判定通过。
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import analyzer

FORMAT = "audit-repro/v1"
KIND = "audit-repro-verification"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

# 比对前剔除的运行元数据：随运行环境/时刻变化，不属于可复现内容
_RESULT_RUNTIME_FIELDS = ("audit_id", "created_at", "filtered", "filter")
_CONFLICT_RUNTIME_FIELDS = ("review",)
_SUMMARY_RUNTIME_FIELDS = ("review",)

# 顶层字段的固定比对顺序（其余字段按键名排序随后），保证“首个不一致字段”确定
_SECTION_ORDER = (
    "manifest_name",
    "status",
    "summary",
    "nodes",
    "edges",
    "conflicts",
    "unresolved",
    "warnings",
)


class BundleFormatError(ValueError):
    """复现包格式错误（API 层转为 422，消息需明确指出问题字段）。"""


# --- 稳定序列化与摘要 ---------------------------------------------------------


def canonical_json(obj: Any) -> str:
    """稳定序列化：键名排序、紧凑分隔符、保留非 ASCII 字符。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(obj: Any) -> str:
    """对任意 JSON 值按稳定序列化计算 SHA-256 十六进制摘要。"""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


# --- 导出 --------------------------------------------------------------------


def build_bundle(
    audit_id: Optional[int],
    name: str,
    manifest: Any,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """把原始 manifest 与保存的审计结果打包为复现包（含两者 SHA-256 摘要）。"""
    return {
        "format": FORMAT,
        "name": name,
        "audit_id": audit_id,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "digests": {
            "manifest_sha256": sha256_hex(manifest),
            "result_sha256": sha256_hex(result),
        },
        "manifest": manifest,
        "result": result,
    }


# --- 核验 --------------------------------------------------------------------


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BundleFormatError(message)


def _validate_bundle(bundle: Any) -> Dict[str, Any]:
    """校验复现包结构，返回规范化后的关键字段；格式错误抛 BundleFormatError。"""
    _require(isinstance(bundle, dict), "复现包必须是 JSON 对象（顶层为 {…}）。")
    fmt = bundle.get("format")
    _require(
        fmt == FORMAT,
        "复现包格式版本不支持：%r，应为 %r。"
        % (fmt if isinstance(fmt, str) else fmt, FORMAT),
    )
    name = bundle.get("name")
    _require(isinstance(name, str) and bool(name.strip()), "复现包缺少有效的 name（审计名称）字段。")

    digests = bundle.get("digests")
    _require(isinstance(digests, dict), "复现包缺少 digests 对象（应含 manifest_sha256 / result_sha256）。")
    for key in ("manifest_sha256", "result_sha256"):
        value = digests.get(key)
        _require(isinstance(value, str), "复现包 digests.%s 缺失或不是字符串。" % key)
        _require(
            bool(_DIGEST_RE.match(value)),
            "复现包 digests.%s 形式不正确：应为 64 位小写十六进制 SHA-256 摘要，实际为 %r。"
            % (key, value),
        )

    _require("manifest" in bundle, "复现包缺少 manifest 字段（原始 manifest）。")
    _require(
        isinstance(bundle["manifest"], dict),
        "复现包 manifest 必须是 JSON 对象，实际为 %s。" % type(bundle["manifest"]).__name__,
    )
    _require("result" in bundle, "复现包缺少 result 字段（保存的审计结果）。")
    _require(
        isinstance(bundle["result"], dict),
        "复现包 result 必须是 JSON 对象，实际为 %s。" % type(bundle["result"]).__name__,
    )
    return {
        "name": name.strip(),
        "digests": digests,
        "manifest": bundle["manifest"],
        "result": bundle["result"],
    }


def strip_runtime(result: Dict[str, Any]) -> Dict[str, Any]:
    """剔除审计结果中的运行元数据（审计 id、时间、复核标记等），返回新字典。"""
    cleaned = {k: v for k, v in result.items() if k not in _RESULT_RUNTIME_FIELDS}
    summary = cleaned.get("summary")
    if isinstance(summary, dict):
        cleaned["summary"] = {
            k: v for k, v in summary.items() if k not in _SUMMARY_RUNTIME_FIELDS
        }
    conflicts = cleaned.get("conflicts")
    if isinstance(conflicts, list):
        cleaned["conflicts"] = [
            {k: v for k, v in c.items() if k not in _CONFLICT_RUNTIME_FIELDS}
            if isinstance(c, dict)
            else c
            for c in conflicts
        ]
    return cleaned


def _first_diff(stored: Any, recomputed: Any, path: str) -> Optional[Dict[str, Any]]:
    """深度比对两个 JSON 值，返回首个不一致处（字典按键名排序、列表按下标）。"""
    if isinstance(stored, bool) != isinstance(recomputed, bool):
        return {"field": path, "stored": stored, "recomputed": recomputed}
    if isinstance(stored, dict) and isinstance(recomputed, dict):
        for key in sorted(set(stored) | set(recomputed)):
            child = "%s.%s" % (path, key) if path else key
            if key not in stored:
                return {"field": child, "stored": "<缺失>", "recomputed": recomputed[key]}
            if key not in recomputed:
                return {"field": child, "stored": stored[key], "recomputed": "<缺失>"}
            diff = _first_diff(stored[key], recomputed[key], child)
            if diff is not None:
                return diff
        return None
    if isinstance(stored, list) and isinstance(recomputed, list):
        common = min(len(stored), len(recomputed))
        for index in range(common):
            diff = _first_diff(
                stored[index], recomputed[index], "%s[%d]" % (path, index)
            )
            if diff is not None:
                return diff
        if len(stored) != len(recomputed):
            return {
                "field": "%s[%d]" % (path, common),
                "stored": stored[common] if common < len(stored) else "<缺失>",
                "recomputed": recomputed[common] if common < len(recomputed) else "<缺失>",
            }
        return None
    if stored != recomputed:
        return {"field": path, "stored": stored, "recomputed": recomputed}
    return None


def _compare_results(stored: Dict[str, Any], recomputed: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """按固定顺序逐项比对两份审计结果，返回首个不一致字段。"""
    keys = [k for k in _SECTION_ORDER if k in stored or k in recomputed]
    keys += sorted(k for k in set(stored) | set(recomputed) if k not in _SECTION_ORDER)
    for key in keys:
        if key not in stored:
            return {"field": key, "stored": "<缺失>", "recomputed": recomputed[key]}
        if key not in recomputed:
            return {"field": key, "stored": stored[key], "recomputed": "<缺失>"}
        diff = _first_diff(stored[key], recomputed[key], key)
        if diff is not None:
            return diff
    return None


def _short(value: Any, limit: int = 120) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def verify_bundle(bundle: Any) -> Dict[str, Any]:
    """核验复现包：重算摘要 + 用包内 manifest 复算分析结果并逐项比对。

    纯内存只读计算，不触碰数据库。格式错误抛 :class:`BundleFormatError`。
    """
    parts = _validate_bundle(bundle)
    name = parts["name"]
    manifest = parts["manifest"]
    stored_result = parts["result"]
    digests = parts["digests"]

    checks: List[Dict[str, Any]] = []
    first_mismatch: Optional[Dict[str, Any]] = None

    # 1) 摘要重算：稳定键序列化后与包内摘要比对
    digest_actual = {
        "manifest_sha256": sha256_hex(manifest),
        "result_sha256": sha256_hex(stored_result),
    }
    digest_labels = {
        "manifest_sha256": ("manifest_digest", "manifest 摘要（SHA-256）", "manifest"),
        "result_sha256": ("result_digest", "保存结果摘要（SHA-256）", "保存的审计结果"),
    }
    for key in ("manifest_sha256", "result_sha256"):
        check_id, label, target = digest_labels[key]
        expected = digests[key]
        actual = digest_actual[key]
        ok = expected == actual
        checks.append(
            {
                "id": check_id,
                "label": label,
                "ok": ok,
                "expected": expected,
                "actual": actual,
            }
        )
        if not ok and first_mismatch is None:
            first_mismatch = {
                "check": check_id,
                "field": "digests.%s" % key,
                "expected": expected,
                "actual": actual,
                "message": (
                    "包内%s与导出时的摘要不一致（期望 %s…，重算为 %s…）："
                    "文件可能已被修改。"
                    % (target, expected[:12], actual[:12])
                ),
            }

    # 2) 分析器复算：剔除运行元数据后逐项比对
    recomputed = analyzer.analyze_manifest(manifest, name)
    recompute_check: Dict[str, Any] = {
        "id": "recompute",
        "label": "分析器复算比对（剔除审计 id / 时间 / 复核标记）",
    }
    if recomputed.get("status") == "error":
        recompute_check["ok"] = False
        recompute_check["error"] = recomputed.get("error", "manifest 无法解析。")
        if first_mismatch is None:
            first_mismatch = {
                "check": "recompute",
                "field": "manifest",
                "message": "包内 manifest 无法被分析器解析：%s"
                % recomputed.get("error", "未知错误"),
            }
    else:
        diff = _compare_results(strip_runtime(stored_result), strip_runtime(recomputed))
        recompute_check["ok"] = diff is None
        if diff is not None:
            recompute_check["field"] = diff["field"]
            recompute_check["stored"] = diff["stored"]
            recompute_check["recomputed"] = diff["recomputed"]
            if first_mismatch is None:
                first_mismatch = {
                    "check": "recompute",
                    "field": diff["field"],
                    "stored": diff["stored"],
                    "recomputed": diff["recomputed"],
                    "message": (
                        "复算结果与保存结果首个不一致字段为 %s：保存值 %s，复算值 %s。"
                        % (diff["field"], _short(diff["stored"]), _short(diff["recomputed"]))
                    ),
                }
    checks.append(recompute_check)

    ok = all(c["ok"] for c in checks)
    summary = recomputed.get("summary") or {}
    if ok:
        message = (
            "复现包核验通过：两处 SHA-256 摘要一致，分析器复算结果与保存结果完全一致"
            "（节点 %d 个、依赖边 %d 条、冲突/告警 %d 条逐项相同）。"
            % (
                summary.get("packages", 0),
                summary.get("edges", 0),
                summary.get("conflicts", 0) + summary.get("license_warnings", 0),
            )
        )
    else:
        message = "复现包核验未通过：%s" % (first_mismatch or {}).get("message", "存在不一致项。")

    return {
        "kind": KIND,
        "read_only": True,
        "ok": ok,
        "format": FORMAT,
        "name": name,
        "source_audit_id": bundle.get("audit_id"),
        "exported_at": bundle.get("exported_at"),
        "checks": checks,
        "digests": {
            key: {
                "expected": digests[key],
                "actual": digest_actual[key],
                "ok": digests[key] == digest_actual[key],
            }
            for key in ("manifest_sha256", "result_sha256")
        },
        "first_mismatch": first_mismatch,
        "recomputed": {
            "manifest_name": recomputed.get("manifest_name"),
            "status": recomputed.get("status"),
            "packages": summary.get("packages"),
            "edges": summary.get("edges"),
            "conflicts": summary.get("conflicts"),
            "license_warnings": summary.get("license_warnings"),
            "unresolved": summary.get("unresolved"),
            "warnings": summary.get("warnings"),
        },
        "message": message,
    }
