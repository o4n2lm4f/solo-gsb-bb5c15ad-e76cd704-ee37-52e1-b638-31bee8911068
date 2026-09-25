"""根包退役预演（只读）。

根包定义为依赖图中 **没有入边** 的包（没有任何其他包依赖它）。
预演从根包集合中移除选定的一个或多个根包，沿 *使用方 -> 被依赖方*
的依赖边从剩余根包重新计算可达集合，输出：

* ``lost`` —— 因退役失去可达性的包（含被退役的根包本身）；
* ``shared`` —— 退役根包原本可达、但仍被其他（剩余）根包共用的包；
* ``disappearing_conflicts`` —— 退役后祖先不再能沿依赖边约束到被依赖方
  的许可证冲突/告警，每条附原审计的最短依赖路径。

预演是纯内存只读计算：不创建审计、不改动任何复核标记；
原生 manifest 与 CycloneDX 审计结果结构一致，均可直接预演。
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Set

KIND = "root-retirement-rehearsal"

DIRECTION = "依赖边方向：使用方 -> 被依赖方；可达性从剩余根包沿边重算。"


def find_roots(result: Dict[str, Any]) -> List[str]:
    """按节点声明顺序返回所有根包（没有入边的节点）id。"""
    targets = {str(e.get("target")) for e in result.get("edges", []) or []}
    return [
        str(n.get("id"))
        for n in result.get("nodes", []) or []
        if str(n.get("id")) not in targets
    ]


def _adjacency(result: Dict[str, Any]) -> Dict[str, List[str]]:
    adjacency: Dict[str, List[str]] = {}
    for edge in result.get("edges", []) or []:
        adjacency.setdefault(str(edge.get("source")), []).append(str(edge.get("target")))
    return adjacency


def _reachable(adjacency: Dict[str, List[str]], seeds: Any) -> Set[str]:
    """沿 使用方 -> 被依赖方 的边从 seeds 做 BFS，返回可达集合（含 seeds 自身）。"""
    seen = set(seeds)
    queue = deque(seeds)
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _node_brief(node: Dict[str, Any], extra: Dict[str, Any] = None) -> Dict[str, Any]:
    brief = {
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
    if extra:
        brief.update(extra)
    return brief


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


def _duplicates(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    duplicates: List[str] = []
    for item in items:
        if item in seen and item not in duplicates:
            duplicates.append(item)
        seen.add(item)
    return duplicates


def rehearse_retirement(result: Dict[str, Any], retire_ids: List[str]) -> Dict[str, Any]:
    """对一份审计结果做根包退役预演，返回预演报告（只读，不改写输入）。

    ``retire_ids`` 为空时返回预览（仅根包列表，``rehearsed`` 为 False），
    供页面列出可退役的根包；否则执行预演。重复选择、不存在的包、
    非根包（存在入边）、退役全部根包都会抛出 ``ValueError``（API 层转为 422）。
    """
    nodes = result.get("nodes", []) or []
    node_map = {str(n.get("id")): n for n in nodes}
    order = [str(n.get("id")) for n in nodes]
    adjacency = _adjacency(result)
    roots = find_roots(result)
    root_set = set(roots)
    # 每个根包各自的可达集合（根包列表展示 + shared 的 reached_by 复用）
    reach_by_root = {root: _reachable(adjacency, [root]) for root in roots}

    requested = [str(r).strip() for r in (retire_ids or []) if str(r).strip()]
    retired_set = set(requested)

    report = {
        "kind": KIND,
        "read_only": True,
        "direction": DIRECTION,
        "audit": _audit_meta(result),
        "roots": [
            _node_brief(
                node_map[root],
                {"retired": root in retired_set, "reachable": len(reach_by_root[root])},
            )
            for root in roots
        ],
    }

    if not requested:
        # 预览模式：仅返回根包列表，不执行预演
        return report | {
            "rehearsed": False,
            "retired": [],
            "remaining_roots": list(roots),
            "summary": None,
            "lost": [],
            "shared": [],
            "disappearing_conflicts": [],
        }

    # 校验：重复选择 -> 不存在的包 -> 非根包 -> 退役全部根包
    duplicates = _duplicates(requested)
    if duplicates:
        raise ValueError(
            "重复选择退役根包：%s。每个根包只能选择一次。" % "、".join(duplicates)
        )
    unknown = [rid for rid in requested if rid not in node_map]
    if unknown:
        raise ValueError(
            "审计中不存在以下包：%s。退役预演只能选择该审计的根包。" % "、".join(unknown)
        )
    non_roots = [rid for rid in requested if rid not in root_set]
    if non_roots:
        raise ValueError(
            "以下包不是根包（仍被其他包依赖，存在入边）：%s。"
            "根包定义为没有入边的包，请改选根包。" % "、".join(non_roots)
        )
    if retired_set == root_set:
        raise ValueError(
            "不能退役全部根包（共 %d 个）：退役后将没有任何可达入口，"
            "预演无意义，请至少保留一个根包。" % len(roots)
        )

    retired = list(dict.fromkeys(requested))  # 保持请求顺序
    remaining_roots = [root for root in roots if root not in retired_set]

    reachable_before: Set[str] = set()
    for root in roots:
        reachable_before |= reach_by_root[root]
    reachable_after: Set[str] = set()
    for root in remaining_roots:
        reachable_after |= reach_by_root[root]
    retired_reachable: Set[str] = set()
    for root in retired:
        retired_reachable |= reach_by_root[root]

    lost_ids = reachable_before - reachable_after
    shared_ids = retired_reachable & reachable_after

    lost = [
        _node_brief(node_map[nid], {"retired_root": nid in retired_set})
        for nid in order
        if nid in lost_ids
    ]
    shared = [
        _node_brief(
            node_map[nid],
            {"reached_by": [root for root in remaining_roots if nid in reach_by_root[root]]},
        )
        for nid in order
        if nid in shared_ids
    ]

    # 冲突消失 <=> 剩余图中祖先不再能沿依赖边到达被依赖方。
    # （可达性沿边单调：祖先仍可达时其出闭包整体仍可达，因此这等价于
    # “祖先或被依赖方失去可达性”；这里按可达性重算，语义与可达集合一致。）
    reach_cache: Dict[str, Set[str]] = {
        root: reach_by_root[root] for root in remaining_roots
    }

    def reachable_from(ancestor: str) -> Set[str]:
        if ancestor not in reach_cache:
            reach_cache[ancestor] = (
                _reachable(adjacency, [ancestor]) if ancestor in reachable_after else set()
            )
        return reach_cache[ancestor]

    disappearing: List[Dict[str, Any]] = []
    for conflict in result.get("conflicts", []) or []:
        ancestor = str(conflict.get("ancestor"))
        node = str(conflict.get("node"))
        if node not in reachable_from(ancestor):
            disappearing.append(dict(conflict))  # 拷贝，附原最短路径 path

    summary = {
        "roots": len(roots),
        "retired": len(retired),
        "remaining_roots": len(remaining_roots),
        "reachable_before": len(reachable_before),
        "reachable_after": len(reachable_after),
        "lost": len(lost),
        "shared": len(shared),
        "disappearing_conflicts": len(disappearing),
        "disappearing_errors": sum(1 for c in disappearing if c.get("severity") == "error"),
        "disappearing_warnings": sum(1 for c in disappearing if c.get("severity") == "warning"),
    }

    return report | {
        "rehearsed": True,
        "retired": retired,
        "remaining_roots": remaining_roots,
        "summary": summary,
        "lost": lost,
        "shared": shared,
        "disappearing_conflicts": disappearing,
    }
