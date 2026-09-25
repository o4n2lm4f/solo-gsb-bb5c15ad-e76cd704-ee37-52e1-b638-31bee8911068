"""两次审计结果对比。

按 *包名 + 版本*（即规范化后的节点 id ``name@version``）配对两份审计的节点，
再按 ``(ancestor, node)`` 配对许可证冲突/告警，输出：

* ``added``   —— 仅存在于目标审计（target）的冲突/告警；
* ``removed`` —— 仅存在于基准审计（base）的冲突/告警；
* ``changed`` —— 双方都存在但严重程度/判定状态/许可证/最短路径发生变化；

每条记录都携带双方各自的冲突对象（含最短依赖路径），缺失一侧为 ``null``。
对比是纯只读计算，不会写入任何新审计。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"
UNCHANGED = "unchanged"

# 人类可读的变化字段说明
FIELD_LABELS: Dict[str, str] = {
    "severity": "严重程度（硬冲突/告警）",
    "status": "兼容判定状态",
    "ancestor_license": "祖先节点许可证",
    "node_license": "被依赖节点许可证",
    "path": "最短依赖路径",
}


def _audit_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    summary = result.get("summary") or {}
    return {
        "audit_id": result.get("audit_id"),
        "manifest_name": result.get("manifest_name"),
        "status": result.get("status"),
        "created_at": result.get("created_at"),
        "packages": summary.get("packages"),
        "edges": summary.get("edges"),
        "conflicts": summary.get("conflicts"),
        "license_warnings": summary.get("license_warnings"),
    }


def _node_brief(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "license_raw": node.get("license_raw"),
        "license_display": node.get("license_display"),
        "license": node.get("license"),
        "license_known": node.get("license_known"),
        "license_category": node.get("license_category"),
        "license_multi": node.get("license_multi", False),
        "license_candidates": node.get("license_candidates", []),
        "license_tokens": node.get("license_tokens", []),
        "conflict_count": node.get("conflict_count", 0),
    }


def _conflict_index(
    result: Dict[str, Any],
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for conflict in result.get("conflicts", []):
        # 分析器对同一 (ancestor, node) 只产出一条最短路径冲突；
        # 这里仍做兜底覆盖，避免历史脏数据导致对比崩溃。
        index[(conflict["ancestor"], conflict["node"])] = conflict
    return index


def _conflict_fields_changed(
    base: Dict[str, Any],
    target: Dict[str, Any],
    base_nodes: Dict[str, Dict[str, Any]],
    target_nodes: Dict[str, Dict[str, Any]],
) -> List[str]:
    changed: List[str] = []
    if base.get("severity") != target.get("severity"):
        changed.append("severity")
    if base.get("status") != target.get("status"):
        changed.append("status")

    ancestor, node = base["ancestor"], base["node"]
    base_ancestor = base_nodes.get(ancestor)
    target_ancestor = target_nodes.get(ancestor)
    if (
        base.get("ancestor_license") != target.get("ancestor_license")
        or (
            base_ancestor is not None
            and target_ancestor is not None
            and base_ancestor.get("license") != target_ancestor.get("license")
        )
    ):
        changed.append("ancestor_license")

    base_node = base_nodes.get(node)
    target_node = target_nodes.get(node)
    if (
        base.get("node_license") != target.get("node_license")
        or (
            base_node is not None
            and target_node is not None
            and base_node.get("license") != target_node.get("license")
        )
    ):
        changed.append("node_license")

    if base.get("path") != target.get("path"):
        changed.append("path")
    return changed


def _finding_sort_key(side: Dict[str, Any]) -> Tuple[int, int, str, str]:
    return (
        0 if side.get("severity") == "error" else 1,
        int(side.get("distance", 0)),
        str(side.get("node", "")),
        str(side.get("ancestor", "")),
    )


def _make_finding(
    key: Tuple[str, str],
    change: str,
    base: Optional[Dict[str, Any]],
    target: Optional[Dict[str, Any]],
    fields_changed: Optional[List[str]] = None,
) -> Dict[str, Any]:
    present = target if target is not None else base
    assert present is not None
    return {
        "change": change,
        "ancestor": key[0],
        "node": key[1],
        "base": base,
        "target": target,
        "fields_changed": fields_changed or [],
        "path_changed": "path" in (fields_changed or []),
        # 便于不展开嵌套对象即可渲染徽标
        "severity_base": base.get("severity") if base else None,
        "severity_target": target.get("severity") if target else None,
        "distance_base": base.get("distance") if base else None,
        "distance_target": target.get("distance") if target else None,
        "sort_key": _finding_sort_key(present),
    }


def _pair_nodes(
    base_nodes: Dict[str, Dict[str, Any]],
    target_nodes: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    paired: List[Dict[str, Any]] = []
    for nid in sorted(set(base_nodes) | set(target_nodes)):
        in_base = base_nodes.get(nid)
        in_target = target_nodes.get(nid)
        if in_base is None:
            change = ADDED
            license_changed = True
            delta: Optional[int] = in_target.get("conflict_count", 0)
        elif in_target is None:
            change = REMOVED
            license_changed = True
            delta = -in_base.get("conflict_count", 0)
        else:
            change = UNCHANGED
            license_changed = in_base.get("license") != in_target.get("license")
            delta = in_target.get("conflict_count", 0) - in_base.get("conflict_count", 0)

        sample = in_target or in_base
        paired.append(
            {
                "id": nid,
                "name": sample.get("name"),
                "version": sample.get("version"),
                "version_unspecified": sample.get("version_unspecified", False),
                "change": change,
                "license_changed": license_changed,
                "conflict_delta": delta,
                "base": _node_brief(in_base) if in_base else None,
                "target": _node_brief(in_target) if in_target else None,
            }
        )
    # 有变化的节点（新增/消失/许可证变更）排前面
    paired.sort(key=lambda item: (item["change"] == UNCHANGED and not item["license_changed"], item["id"]))
    return paired


def compare_audits(base: Dict[str, Any], target: Dict[str, Any]) -> Dict[str, Any]:
    """对比两份完整审计结果字典（``analyzer.analyze_manifest`` 的产物）。"""
    base_nodes_map = {n["id"]: n for n in base.get("nodes", [])}
    target_nodes_map = {n["id"]: n for n in target.get("nodes", [])}
    base_conflicts = _conflict_index(base)
    target_conflicts = _conflict_index(target)

    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []

    for key in sorted(set(base_conflicts) | set(target_conflicts)):
        in_base = base_conflicts.get(key)
        in_target = target_conflicts.get(key)
        if in_base is None:
            added.append(_make_finding(key, ADDED, None, in_target))
        elif in_target is None:
            removed.append(_make_finding(key, REMOVED, in_base, None))
        else:
            fields_changed = _conflict_fields_changed(
                in_base, in_target, base_nodes_map, target_nodes_map
            )
            if fields_changed:
                changed.append(
                    _make_finding(key, CHANGED, in_base, in_target, fields_changed)
                )

    for bucket in (added, removed, changed):
        bucket.sort(key=lambda item: item["sort_key"])
        for item in bucket:
            item.pop("sort_key", None)

    nodes = _pair_nodes(base_nodes_map, target_nodes_map)

    def _errors(bucket: List[Dict[str, Any]]) -> int:
        return sum(
            1
            for item in bucket
            if (item["target"] or item["base"]).get("severity") == "error"
        )

    return {
        "kind": "audit-comparison",
        "read_only": True,
        "direction": "base -> target：added 表示仅目标审计存在，removed 表示仅基准审计存在。",
        "field_labels": FIELD_LABELS,
        "base": _audit_meta(base),
        "target": _audit_meta(target),
        "summary": {
            "nodes": {
                "added": sum(1 for n in nodes if n["change"] == ADDED),
                "removed": sum(1 for n in nodes if n["change"] == REMOVED),
                "matched": sum(1 for n in nodes if n["change"] == UNCHANGED),
                "license_changed": sum(1 for n in nodes if n["license_changed"] and n["change"] == UNCHANGED),
            },
            "findings": {
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
                "added_errors": _errors(added),
                "removed_errors": _errors(removed),
                "changed_errors": _errors(changed),
            },
        },
        "nodes": nodes,
        "added": added,
        "removed": removed,
        "changed": changed,
    }
