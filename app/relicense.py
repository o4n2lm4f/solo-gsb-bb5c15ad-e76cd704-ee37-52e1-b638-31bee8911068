"""单包许可证替换预演（只读）。

对一条已保存的审计，仅把 **一个包节点** 的许可证替换为候选 SPDX 许可证，
沿 *原依赖图*（节点与依赖边完全不变）重算传递兼容判定与最短冲突路径，
再按 ``(祖先包, 被依赖包)`` 配对原结果与预演结果，输出：

* ``added``   —— 仅预演结果存在的冲突/告警（替换后新增）；
* ``removed`` —— 仅原结果存在的冲突/告警（替换后消失）；
* ``changed`` —— 两侧都存在但严重程度/判定状态/许可证发生变化的配对项；

每条记录两侧均携带完整冲突对象（含各自的最短依赖路径），并汇总硬冲突数、
告警数与冲突总数的净变化。配对与变化检测复用 ``compare`` 模块，
重算复用 ``analyzer._build_result``（同一套 BFS 传递约束与最短路径逻辑）。

预演是纯内存只读计算：不创建审计、不改动复核标记；
原生 manifest 与 CycloneDX 审计结果结构一致，均可直接预演。
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from . import analyzer, compare as compare_mod, licenses as lic

KIND = "license-replacement-rehearsal"

DIRECTION = "依赖边方向：使用方 -> 被依赖方；仅替换目标节点许可证，沿原依赖图重算。"

# analyzer._build_result 由 unresolved 条目再生的告警前缀（用于从已存告警中剥离，避免重复）
_UNRESOLVED_PREFIX = "未解析依赖："


def candidate_licenses() -> List[Dict[str, str]]:
    """内置兼容矩阵支持的全部候选 SPDX 许可证（按矩阵声明顺序）。"""
    return [
        {
            "token": token,
            "category": category,
            "category_label": lic.CATEGORY_LABELS[category],
        }
        for token, category in lic.CATEGORIES.items()
    ]


def _audit_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    summary = result.get("summary") or {}
    return {
        "audit_id": result.get("audit_id"),
        "manifest_name": result.get("manifest_name"),
        "status": result.get("status"),
        "created_at": result.get("created_at"),
        "source_format": result.get("source_format"),
        "packages": summary.get("packages"),
        "edges": summary.get("edges"),
        "conflicts": summary.get("conflicts"),
        "license_warnings": summary.get("license_warnings"),
    }


def _node_brief(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "version": node.get("version"),
        "version_unspecified": node.get("version_unspecified", False),
        "license_raw": node.get("license_raw"),
        "license_display": node.get("license_display"),
        "license": node.get("license"),
        "license_known": node.get("license_known"),
        "license_category": node.get("license_category"),
        "license_multi": node.get("license_multi", False),
        "license_candidates": node.get("license_candidates", []),
        "conflict_count": node.get("conflict_count", 0),
    }


def _resolve_package(result: Dict[str, Any], package: str) -> Tuple[str, Dict[str, Any]]:
    """把用户输入解析为审计中的节点：精确 id -> 大小写不敏感 id -> 唯一包名。

    找不到或包名对应多个版本时抛出 ``ValueError``（API 层转为 422）。
    """
    nodes = result.get("nodes", []) or []
    text = package.strip()
    lowered = text.lower()
    for node in nodes:
        if str(node.get("id")) == text:
            return str(node.get("id")), node
    for node in nodes:
        if str(node.get("id")).lower() == lowered:
            return str(node.get("id")), node
    matches = [n for n in nodes if str(n.get("name") or "").lower() == lowered]
    if len(matches) == 1:
        return str(matches[0].get("id")), matches[0]
    if len(matches) > 1:
        raise ValueError(
            "包名 %r 在该审计中对应多个版本：%s，请用 name@version 指定要替换的节点。"
            % (text, "、".join(sorted(str(n.get("id")) for n in matches)))
        )
    raise ValueError(
        "审计中不存在包：%s。许可证替换预演只能选择该审计已声明的包节点。" % text
    )


def _normalize_candidate(raw: str) -> Dict[str, Any]:
    """规范化候选许可证；不在内置矩阵中时抛出 ``ValueError``（API 层转为 422）。"""
    _display, token, known = lic.normalize_license(raw)
    if not known:
        raise ValueError(
            "候选许可证 %r 不在内置兼容矩阵中，无法预演。可选 SPDX 标识：%s。"
            % (raw, "、".join(lic.CATEGORIES.keys()))
        )
    # 用规范标识本身作为展示文本（候选是矩阵内的 SPDX 标识，而非用户原文）
    return lic.license_info(token)


def _recompute_with_license(
    result: Dict[str, Any],
    target_id: str,
    info: Dict[str, Any],
) -> Dict[str, Any]:
    """拷贝原审计的节点/边，仅替换目标节点许可证后沿原图重算（不改写输入）。"""
    nodes = result.get("nodes", []) or []
    order: List[str] = []
    node_map: Dict[str, Dict[str, Any]] = {}
    for node in nodes:
        cloned = copy.deepcopy(node)
        cloned["constraints"] = []
        cloned["conflict_count"] = 0
        node_map[str(cloned["id"])] = cloned
        order.append(str(cloned["id"]))

    target = node_map[target_id]
    target["license_raw"] = info["token"]
    target["license_display"] = info["display"]
    target["license"] = info["token"]
    target["license_known"] = True
    target["license_category"] = info["category"]
    # 替换预演的候选恒为单个矩阵许可证，重置多候选相关字段
    target["license_multi"] = False
    target["license_candidates"] = [
        {
            "token": info["token"],
            "display": info["display"],
            "category": info["category"],
            "category_label": info["category_label"],
        }
    ]
    target["license_tokens"] = [info["token"]]

    edges = copy.deepcopy(result.get("edges", []) or [])
    unresolved = copy.deepcopy(result.get("unresolved", []) or [])
    # 已存告警 = 解析告警 + 未解析告警；_build_result 会按 unresolved 再生后者，
    # 这里只回传解析告警，避免重复。
    regenerated = {
        "%s%s -> %s（%s）" % (_UNRESOLVED_PREFIX, u.get("source"), u.get("reference"), u.get("reason"))
        for u in unresolved
    }
    parse_warnings = [w for w in (result.get("warnings") or []) if w not in regenerated]

    display_name = "%s（预演：%s 许可证替换为 %s）" % (
        result.get("manifest_name") or "audit",
        target_id,
        info["display"],
    )
    recomputed = analyzer._build_result(
        display_name, None, node_map, order, edges, unresolved, parse_warnings
    )
    if result.get("source_format"):
        recomputed["source_format"] = result["source_format"]
    return recomputed


def rehearse_relicense(
    result: Dict[str, Any],
    package: Optional[str] = None,
    license: Optional[str] = None,
) -> Dict[str, Any]:
    """对一份审计结果做单包许可证替换预演，返回预演报告（只读，不改写输入）。

    ``package`` 与 ``license`` 都缺省时返回预览（``rehearsed`` 为 False）：
    可选包列表与内置矩阵候选许可证列表，供页面填充下拉框。
    两者必须同时提供才能执行预演；包不存在、包名歧义（多版本）或候选许可证
    不在内置矩阵时抛出 ``ValueError``（API 层转为 422）。
    """
    package_text = (package or "").strip()
    license_text = (license or "").strip()

    report = {
        "kind": KIND,
        "read_only": True,
        "direction": DIRECTION,
        "audit": _audit_meta(result),
        "packages": [_node_brief(n) for n in result.get("nodes", []) or []],
        "candidate_licenses": candidate_licenses(),
    }

    if not package_text and not license_text:
        # 预览模式：仅返回可选包与候选许可证，不执行预演
        return report | {
            "rehearsed": False,
            "target": None,
            "rehearsal": None,
            "summary": None,
            "comparison": None,
        }
    if not package_text or not license_text:
        raise ValueError(
            "package 与 license 必须同时提供才能预演（或同时留空以获取可选列表）。"
        )

    target_id, target_node = _resolve_package(result, package_text)
    info = _normalize_candidate(license_text)

    recomputed = _recompute_with_license(result, target_id, info)
    # 基准 = 原审计结果，目标 = 预演结果：added 为替换后新增，removed 为替换后消失
    comparison = compare_mod.compare_audits(result, recomputed)
    findings = comparison["summary"]["findings"]

    base_summary = result.get("summary") or {}
    new_summary = recomputed.get("summary") or {}
    errors_before = int(base_summary.get("conflicts") or 0)
    errors_after = int(new_summary.get("conflicts") or 0)
    warnings_before = int(base_summary.get("license_warnings") or 0)
    warnings_after = int(new_summary.get("license_warnings") or 0)

    summary = {
        "conflicts_before": errors_before,
        "conflicts_after": errors_after,
        "conflicts_net": errors_after - errors_before,
        "warnings_before": warnings_before,
        "warnings_after": warnings_after,
        "warnings_net": warnings_after - warnings_before,
        "total_before": errors_before + warnings_before,
        "total_after": errors_after + warnings_after,
        "total_net": (errors_after + warnings_after) - (errors_before + warnings_before),
        "added": findings["added"],
        "removed": findings["removed"],
        "changed": findings["changed"],
        "severity_changed": sum(
            1
            for item in comparison["changed"]
            if "severity" in item.get("fields_changed", [])
        ),
        "added_errors": findings["added_errors"],
        "removed_errors": findings["removed_errors"],
    }

    return report | {
        "rehearsed": True,
        "target": {
            "id": target_id,
            "name": target_node.get("name"),
            "version": target_node.get("version"),
            "version_unspecified": target_node.get("version_unspecified", False),
            "input": {"package": package_text, "license": license_text},
            "license_before": {
                "display": target_node.get("license_display"),
                "token": target_node.get("license"),
                "known": target_node.get("license_known"),
                "category": target_node.get("license_category"),
            },
            "license_after": {
                "display": info["display"],
                "token": info["token"],
                "known": True,
                "category": info["category"],
                "category_label": info["category_label"],
            },
        },
        "rehearsal": _audit_meta(recomputed),
        "summary": summary,
        "comparison": comparison,
    }
