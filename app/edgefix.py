"""未解析依赖补边预演（只读）。

对一条已保存的审计，从其 **源包仍存在** 的未解析依赖引用中选一条，再选一个
**现有目标包**，服务端只在内存中补一条 *使用方 -> 被依赖方* 的依赖边并移除
所选未解析项（其余节点、许可证与边完全不变），随后重算传递约束与最短冲突路径，
并按 ``(祖先包, 被依赖包)`` 配对原结果与预演结果，输出：

* ``added``   —— 仅预演结果存在的冲突/告警（补边后新增）；
* ``changed`` —— 两侧都存在但最短依赖路径发生变化的配对项（补边后出现更短路径）；
* ``remaining_unresolved`` —— 补边后剩余的未解析依赖项；
* ``summary`` —— 硬冲突数、告警数、冲突总数与未解析数的净变化。

由于只新增一条边、不改动任何节点与许可证，原有冲突不会消失（``removed`` 恒为空），
但原冲突的最短路径可能因新边而缩短，此类配对项进入 ``changed``。

预演是纯内存只读计算：不创建审计、不改动复核标记；
原生 manifest 与 CycloneDX 审计结果结构一致，均可直接预演。
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from . import analyzer, compare as compare_mod

KIND = "unresolved-edge-rehearsal"

DIRECTION = "依赖边方向：使用方 -> 被依赖方；仅补一条边并移除所选未解析项，沿新图重算。"

EDGE_SOURCE = "edgefix-rehearsal"

# analyzer._build_result 由 unresolved 条目再生的告警前缀（用于从已存告警中剥离，避免重复）
_UNRESOLVED_PREFIX = "未解析依赖："


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
        "unresolved": summary.get("unresolved"),
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


def _selectable_unresolved(
    result: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """把未解析项拆成（源包仍存在、可补边）与（源包已不存在、不可补边）两组。

    可选条目附带 ``existing_targets``（源包现有出边的目标），供页面排除重复边。
    """
    node_ids = {str(n.get("id")) for n in result.get("nodes", []) or []}
    targets_by_source: Dict[str, List[str]] = {}
    for edge in result.get("edges", []) or []:
        targets_by_source.setdefault(str(edge.get("source")), []).append(str(edge.get("target")))

    selectable: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for item in result.get("unresolved", []) or []:
        source = str(item.get("source"))
        entry = {
            "source": source,
            "reference": item.get("reference"),
            "reason": item.get("reason"),
        }
        if source in node_ids:
            entry["existing_targets"] = list(targets_by_source.get(source, []))
            selectable.append(entry)
        else:
            skipped.append(entry)
    return selectable, skipped


def _find_unresolved(
    result: Dict[str, Any], source: str, reference: str
) -> Dict[str, Any]:
    """按 (source, reference) 精确匹配一条未解析项；找不到时抛出 ``ValueError``。"""
    for item in result.get("unresolved", []) or []:
        if str(item.get("source")) == source and str(item.get("reference")) == reference:
            return item
    raise ValueError(
        "审计中不存在未解析引用：%s -> %s。请从该审计的未解析依赖列表中选择。"
        % (source, reference)
    )


def _resolve_target(result: Dict[str, Any], target: str) -> str:
    """把用户输入解析为审计中的节点 id：精确 id -> 大小写不敏感 id -> 唯一包名。

    找不到或包名对应多个版本时抛出 ``ValueError``（API 层转为 422）。
    """
    nodes = result.get("nodes", []) or []
    text = target.strip()
    lowered = text.lower()
    for node in nodes:
        if str(node.get("id")) == text:
            return str(node.get("id"))
    for node in nodes:
        if str(node.get("id")).lower() == lowered:
            return str(node.get("id"))
    matches = [n for n in nodes if str(n.get("name") or "").lower() == lowered]
    if len(matches) == 1:
        return str(matches[0].get("id"))
    if len(matches) > 1:
        raise ValueError(
            "包名 %r 在该审计中对应多个版本：%s，请用 name@version 指定目标包。"
            % (text, "、".join(sorted(str(n.get("id")) for n in matches)))
        )
    raise ValueError(
        "审计中不存在目标包：%s。补边预演只能选择该审计已声明的包节点作为目标。" % text
    )


def _recompute_with_edge(
    result: Dict[str, Any],
    source_id: str,
    target_id: str,
    chosen: Dict[str, Any],
) -> Dict[str, Any]:
    """拷贝原审计的节点/边/未解析项，补一条边并移除所选未解析项后重算（不改写输入）。"""
    order: List[str] = []
    node_map: Dict[str, Dict[str, Any]] = {}
    for node in result.get("nodes", []) or []:
        cloned = copy.deepcopy(node)
        cloned["constraints"] = []
        cloned["conflict_count"] = 0
        node_map[str(cloned["id"])] = cloned
        order.append(str(cloned["id"]))

    edges = copy.deepcopy(result.get("edges", []) or [])
    edges.append({"source": source_id, "target": target_id, "from": EDGE_SOURCE})

    # 移除所选未解析项，其余未解析项原样保留
    unresolved = [
        copy.deepcopy(item)
        for item in result.get("unresolved", []) or []
        if not (
            str(item.get("source")) == str(chosen.get("source"))
            and str(item.get("reference")) == str(chosen.get("reference"))
        )
    ]
    # 已存告警 = 解析告警 + 未解析告警；_build_result 会按剩余 unresolved 再生后者，
    # 这里只回传解析告警，避免重复。
    regenerated = {
        "%s%s -> %s（%s）" % (_UNRESOLVED_PREFIX, u.get("source"), u.get("reference"), u.get("reason"))
        for u in result.get("unresolved", []) or []
    }
    parse_warnings = [w for w in (result.get("warnings") or []) if w not in regenerated]

    display_name = "%s（预演：补边 %s -> %s）" % (
        result.get("manifest_name") or "audit",
        source_id,
        target_id,
    )
    recomputed = analyzer._build_result(
        display_name, None, node_map, order, edges, unresolved, parse_warnings
    )
    if result.get("source_format"):
        recomputed["source_format"] = result["source_format"]
    return recomputed


def rehearse_edgefix(
    result: Dict[str, Any],
    source: Optional[str] = None,
    reference: Optional[str] = None,
    target: Optional[str] = None,
) -> Dict[str, Any]:
    """对一份审计结果做未解析依赖补边预演，返回预演报告（只读，不改写输入）。

    三个参数都缺省时返回预览（``rehearsed`` 为 False）：源包仍存在的未解析引用
    列表与可选目标包列表，供页面填充下拉框。三者必须同时提供才能执行预演；
    引用或目标无效、补成自依赖（源包即目标包）或重复边（源包已依赖目标包）
    都会抛出 ``ValueError``（API 层转为 422）。
    """
    source_text = (source or "").strip()
    reference_text = (reference or "").strip()
    target_text = (target or "").strip()

    selectable, skipped = _selectable_unresolved(result)
    report = {
        "kind": KIND,
        "read_only": True,
        "direction": DIRECTION,
        "audit": _audit_meta(result),
        "unresolved": selectable,
        "unresolved_skipped": skipped,
        "packages": [_node_brief(n) for n in result.get("nodes", []) or []],
    }

    if not source_text and not reference_text and not target_text:
        # 预览模式：仅返回可选未解析引用与目标包列表，不执行预演
        return report | {
            "rehearsed": False,
            "fix": None,
            "rehearsal": None,
            "summary": None,
            "remaining_unresolved": None,
            "comparison": None,
        }
    if not source_text or not reference_text or not target_text:
        raise ValueError(
            "source、reference 与 target 必须同时提供才能预演（或同时留空以获取可选列表）。"
        )

    chosen = _find_unresolved(result, source_text, reference_text)
    node_ids = {str(n.get("id")) for n in result.get("nodes", []) or []}
    if source_text not in node_ids:
        raise ValueError(
            "未解析引用 %s -> %s 的源包不在该审计的节点中，无法补边。"
            "预演只能选择源包仍存在的未解析引用。" % (source_text, reference_text)
        )
    source_id = source_text
    target_id = _resolve_target(result, target_text)

    if source_id == target_id:
        raise ValueError(
            "不能把 %s 的未解析引用补成指向自身的边（自依赖）：%s -> %s。"
            "请选择其他目标包。" % (source_id, source_id, target_id)
        )
    existing_edges = {
        (str(e.get("source")), str(e.get("target"))) for e in result.get("edges", []) or []
    }
    if (source_id, target_id) in existing_edges:
        raise ValueError(
            "依赖边 %s -> %s 已存在，补边会产生重复边。请选择其他目标包。"
            % (source_id, target_id)
        )

    recomputed = _recompute_with_edge(result, source_id, target_id, chosen)
    # 基准 = 原审计结果，目标 = 预演结果：added 为补边后新增，changed 为路径变化
    comparison = compare_mod.compare_audits(result, recomputed)
    findings = comparison["summary"]["findings"]

    base_summary = result.get("summary") or {}
    new_summary = recomputed.get("summary") or {}
    errors_before = int(base_summary.get("conflicts") or 0)
    errors_after = int(new_summary.get("conflicts") or 0)
    warnings_before = int(base_summary.get("license_warnings") or 0)
    warnings_after = int(new_summary.get("license_warnings") or 0)
    unresolved_before = int(base_summary.get("unresolved") or 0)
    unresolved_after = int(new_summary.get("unresolved") or 0)

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
        "unresolved_before": unresolved_before,
        "unresolved_after": unresolved_after,
        "unresolved_net": unresolved_after - unresolved_before,
        "added": findings["added"],
        "removed": findings["removed"],
        "changed": findings["changed"],
        "path_changed": sum(
            1
            for item in comparison["changed"]
            if "path" in item.get("fields_changed", [])
        ),
        "added_errors": findings["added_errors"],
        "removed_errors": findings["removed_errors"],
    }

    return report | {
        "rehearsed": True,
        "fix": {
            "source": source_id,
            "reference": chosen.get("reference"),
            "reason": chosen.get("reason"),
            "target": target_id,
            "edge": {"source": source_id, "target": target_id, "from": EDGE_SOURCE},
            "input": {
                "source": source_text,
                "reference": reference_text,
                "target": target_text,
            },
        },
        "rehearsal": _audit_meta(recomputed),
        "summary": summary,
        "remaining_unresolved": recomputed.get("unresolved", []),
        "comparison": comparison,
    }
