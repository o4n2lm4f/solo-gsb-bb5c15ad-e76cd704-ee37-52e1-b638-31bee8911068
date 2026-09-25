"""最少断边分析（只读）。

对一条已保存审计中的冲突/告警（祖先包 ancestor 经 *使用方 -> 被依赖方*
依赖边约束到被依赖包 target），沿审计保存的现有依赖图计算：要让 ancestor
**不再能够到达** target，至少需要删除多少条、以及删除哪几条依赖边。

这是有向图上的 **s-t 最小边割（minimum s-t edge cut）** 问题，按最大流
最小割定理：

* 以 ancestor 为源点 s、target 为汇点 t，给每条现有依赖边容量 1，
  用 Edmonds-Karp（BFS 增广）计算 s->t 最大流；最大流的流量即
  **最少断边数**，每条增广路对应一条两两边不相交的 ancestor->target
  路径——并行路径、汇合路径都被计入，而不是只看当前最短路径；
* 在最大流残量网络上从 s 做 BFS，原边中“起点可达、终点不可达”的边
  即为一组确定性的最小割边集合（邻接顺序按审计中边的声明顺序，
  结果可复现）；
* 依赖环在 BFS/残量网络中天然安全（节点只访问一次）；反向平行边
  （u->v 与 v->u 同时存在）用标准净流模型处理，容量按方向相加；
* 分析后在删除这些边的图上重新做 BFS，确认 target 确实不再可达。

整个分析是纯内存只读计算：不创建审计、不改动保存的依赖图与任何复核
标记；原生 manifest 与 CycloneDX 审计结果结构一致，均可直接分析。
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

KIND = "minimum-edge-cut"

DIRECTION = "依赖边方向：使用方 -> 被依赖方；删除建议边后从祖先包沿边重算可达性。"

METHOD = (
    "有向图 s-t 最小边割：每条现有依赖边容量为 1，用 Edmonds-Karp（BFS 增广）"
    "求 祖先包 -> 被依赖包 的最大流，最大流流量等于最少断边数；"
    "在最大流残量网络上从祖先包做 BFS，原边中起点可达而终点不可达的边即为"
    "一组确定性最小割边。并行路径、汇合路径与依赖环均纳入计算，不只处理当前最短路径。"
)


class ConflictNotFound(LookupError):
    """审计中找不到指定冲突/告警条目（API 层转为 404）。"""


# --- 图工具 ------------------------------------------------------------------


def _edge_pairs(result: Dict[str, Any]) -> List[Tuple[str, str]]:
    """按审计中保存的顺序返回去重后的 (source, target) 边（保证结果确定）。"""
    pairs: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for edge in result.get("edges", []) or []:
        pair = (str(edge.get("source")), str(edge.get("target")))
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)
    return pairs


def _edge_index(result: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for edge in result.get("edges", []) or []:
        key = (str(edge.get("source")), str(edge.get("target")))
        if key not in index:
            index[key] = edge
    return index


def _adjacency(
    pairs: List[Tuple[str, str]], removed: Optional[Set[Tuple[str, str]]] = None
) -> Dict[str, List[str]]:
    """构建邻接表（邻接顺序与边声明顺序一致，保证 BFS/割边结果确定）。"""
    removed = removed or set()
    adjacency: Dict[str, List[str]] = {}
    for source, target in pairs:
        if (source, target) in removed:
            continue
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])
    return adjacency


def _reachable(adjacency: Dict[str, List[str]], start: str) -> Set[str]:
    """沿 使用方 -> 被依赖方 边从 start 做 BFS，返回可达集合（含 start，天然处理环）。"""
    seen = {start}
    queue: deque[str] = deque([start])
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _shortest_path(adjacency: Dict[str, List[str]], start: str, end: str) -> List[str]:
    """返回 start -> end 的一条最短路径（BFS 唯一前驱，顺序确定）；不可达时为 []。"""
    if start == end:
        return [start]
    parents: Dict[str, Optional[str]] = {start: None}
    queue: deque[str] = deque([start])
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, []):
            if nxt in parents:
                continue
            parents[nxt] = current
            if nxt == end:
                return _reconstruct(parents, start, end)
            queue.append(nxt)
    return []


def _reconstruct(parents: Dict[str, Optional[str]], start: str, end: str) -> List[str]:
    path = [end]
    cur: Optional[str] = end
    while cur != start:
        cur = parents.get(cur)
        if cur is None:
            return []
        path.append(cur)
    path.reverse()
    return path


# --- 最大流 / 最小割（单位容量有向图，Edmonds-Karp） ---------------------------


def _undirected_neighbors(pairs: List[Tuple[str, str]]) -> Dict[str, List[str]]:
    """构建无向邻接表（保留边声明顺序、去重）：残量网络可能沿反向弧增广/访问。"""
    neighbors: Dict[str, List[str]] = {}
    seen: Dict[str, Set[str]] = {}
    for u, v in pairs:
        for a, b in ((u, v), (v, u)):
            bucket = seen.setdefault(a, set())
            neighbors.setdefault(a, [])
            if b not in bucket:
                bucket.add(b)
                neighbors[a].append(b)
    return neighbors


def _edmonds_karp(
    pairs: List[Tuple[str, str]], source: str, sink: str
) -> Tuple[int, Dict[Tuple[str, str], int], Dict[Tuple[str, str], int]]:
    """单位容量有向图上的 Edmonds-Karp（净流模型，反向平行边按方向叠加容量）。

    返回 ``(最大流量, 各有序节点对的容量 c, 最终净流 f)``：
    残量容量 ``r(u,v) = c(u,v) - f(u,v)``，满足 ``f(v,u) = -f(u,v)``。
    增广 BFS 在无向邻接上遍历（残量反向弧对应撤销已有流量，是正确性的
    关键，汇合路径改道依赖它）；邻接顺序严格按审计中边的声明顺序，
    流量与最小割均可复现。
    """
    capacity: Dict[Tuple[str, str], int] = {}
    for u, v in pairs:
        capacity[(u, v)] = capacity.get((u, v), 0) + 1  # 平行边容量叠加（审计边通常已去重）
    neighbors = _undirected_neighbors(pairs)

    flow: Dict[Tuple[str, str], int] = {}

    def residual(u: str, v: str) -> int:
        return capacity.get((u, v), 0) - flow.get((u, v), 0)

    total = 0
    while True:
        # BFS 在残量网络中找 source -> sink 增广路
        parents: Dict[str, Optional[str]] = {source: None}
        queue: deque[str] = deque([source])
        while queue and sink not in parents:
            cur = queue.popleft()
            for nxt in neighbors.get(cur, []):
                if nxt in parents or residual(cur, nxt) <= 0:
                    continue
                parents[nxt] = cur
                queue.append(nxt)
        if sink not in parents:
            break
        # 单位容量，瓶颈恒为 1；沿增广路更新净流
        cur = sink
        while cur != source:
            prev = parents[cur]
            assert prev is not None
            flow[(prev, cur)] = flow.get((prev, cur), 0) + 1
            flow[(cur, prev)] = flow.get((cur, prev), 0) - 1
            cur = prev
        total += 1
    return total, capacity, flow


def _residual_source_side(
    pairs: List[Tuple[str, str]],
    source: str,
    capacity: Dict[Tuple[str, str], int],
    flow: Dict[Tuple[str, str], int],
) -> Set[str]:
    """在最大流残量网络上从 source 做 BFS，返回残量可达节点集合 S（含残量反向弧）。"""
    neighbors = _undirected_neighbors(pairs)
    seen = {source}
    queue: deque[str] = deque([source])
    while queue:
        cur = queue.popleft()
        for nxt in neighbors.get(cur, []):
            if nxt in seen:
                continue
            residual = capacity.get((cur, nxt), 0) - flow.get((cur, nxt), 0)
            if residual <= 0:
                continue
            seen.add(nxt)
            queue.append(nxt)
    return seen


def _decompose_flow_paths(
    pairs: List[Tuple[str, str]],
    flow: Dict[Tuple[str, str], int],
    source: str,
    sink: str,
    count: int,
) -> List[List[str]]:
    """把最终流量分解为 ``count`` 条两两边不相交的 source->sink 路径。

    取净流为正（f(u,v)>0）的弧作为“已用流量弧”，在其上反复做 BFS 取
    source->sink 最短路径并移除该路径上的弧；中间节点满足流守恒，故每次
    移除后仍可继续，直到取出 ``count`` 条。残余已用弧只可能是与 s-t 流
    无关的环流，直接忽略。邻接顺序按边声明顺序，结果确定。
    """
    used: Set[Tuple[str, str]] = {
        (u, v) for (u, v) in pairs if flow.get((u, v), 0) > 0
    }
    paths: List[List[str]] = []
    for _ in range(count):
        # 按审计边声明顺序构建已用弧的邻接表，保证分解出的路径可复现
        used_adjacency = _adjacency([pair for pair in pairs if pair in used])
        path = _shortest_path(used_adjacency, source, sink)
        if not path:
            break  # 余下已用弧为环流，无 s-t 路径（理论上不应在 count 用尽前发生）
        paths.append(path)
        for i in range(len(path) - 1):
            used.discard((path[i], path[i + 1]))
    paths.sort(key=lambda p: (len(p), p))
    return paths


# --- 审计元信息 ---------------------------------------------------------------


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


def find_conflict(result: Dict[str, Any], conflict_id: str) -> Dict[str, Any]:
    """按冲突 id（如 C001）定位审计中的冲突/告警条目；找不到时抛 ConflictNotFound。"""
    cid = str(conflict_id or "").strip()
    for conflict in result.get("conflicts", []) or []:
        if str(conflict.get("id")) == cid:
            return conflict
    raise ConflictNotFound(cid)


def _edge_brief(pair: Tuple[str, str], raw: Optional[Dict[str, Any]], on_shortest: bool) -> Dict[str, Any]:
    source, target = pair
    return {
        "source": source,
        "target": target,
        "id": "%s -> %s" % (source, target),
        "from": raw.get("from") if raw is not None else None,
        "on_original_shortest_path": on_shortest,
    }


def analyze_cut(result: Dict[str, Any], conflict_id: str) -> Dict[str, Any]:
    """对一条冲突/告警计算最少断边集合，返回分析报告（纯只读，不改写输入）。

    审计存在但冲突条目不存在时抛 :class:`ConflictNotFound`（API 层转为 404）。
    """
    conflict = find_conflict(result, conflict_id)
    source = str(conflict.get("ancestor"))
    target = str(conflict.get("node"))
    if source == target:
        raise ValueError(
            "冲突 %s 的祖先包与被依赖包相同（%s），无法通过删除依赖边隔离，"
            "最少断边分析仅适用于两个不同节点之间的约束。" % (conflict.get("id"), source)
        )

    pairs = _edge_pairs(result)
    raw_by_pair = _edge_index(result)
    adjacency = _adjacency(pairs)

    original_path = [str(n) for n in conflict.get("path", [])]
    original_edges: Set[Tuple[str, str]] = {
        (original_path[i], original_path[i + 1])
        for i in range(len(original_path) - 1)
    }

    reachable_before = target in _reachable(adjacency, source)

    # 最大流 = 最少断边数；残量源侧 S 给出确定性的一组最小割边。
    flow, capacity, net_flow = _edmonds_karp(pairs, source, target)
    if flow == 0:
        cut_pairs: List[Tuple[str, str]] = []
    else:
        source_side = _residual_source_side(pairs, source, capacity, net_flow)
        cut_pairs = [
            (u, v) for (u, v) in pairs if u in source_side and v not in source_side
        ]

    # 边不相交见证路径（数量必须等于最少断边数）
    flow_paths = _decompose_flow_paths(pairs, net_flow, source, target, flow)

    removed = set(cut_pairs)
    adjacency_after = _adjacency(pairs, removed)
    reachable_after_set = _reachable(adjacency_after, source)
    reachable_after = target in reachable_after_set
    residual_path = _shortest_path(adjacency_after, source, target)

    # 严格自洽校验：任何一条不满足都属于内部错误，不能静默给出错误建议。
    if flow > 0:
        assert len(cut_pairs) == flow, "最小割边数 %d 与最大流 %d 不一致" % (
            len(cut_pairs),
            flow,
        )
        assert len(flow_paths) == flow, "边不相交路径数 %d 与最大流 %d 不一致" % (
            len(flow_paths),
            flow,
        )
        assert not reachable_after, "删除建议边后 %s 仍可到达 %s" % (source, target)
        assert not residual_path, "断边后仍存在 %s -> %s 路径" % (source, target)
        for fpath in flow_paths:
            hits = [
                i
                for i in range(len(fpath) - 1)
                if (fpath[i], fpath[i + 1]) in removed
            ]
            assert len(hits) == 1, "见证路径 %s 被割边命中 %d 次" % (fpath, len(hits))

    cut_edges = [
        _edge_brief(pair, raw_by_pair.get(pair), pair in original_edges)
        for pair in cut_pairs
    ]
    cut_on_shortest = sum(1 for e in cut_edges if e["on_original_shortest_path"])

    return {
        "kind": KIND,
        "read_only": True,
        "direction": DIRECTION,
        "method": METHOD,
        "deterministic": True,
        "audit": _audit_meta(result),
        "conflict": {
            "id": conflict.get("id"),
            "kind": conflict.get("kind"),
            "severity": conflict.get("severity"),
            "status": conflict.get("status"),
            "ancestor": source,
            "node": target,
            "ancestor_license": conflict.get("ancestor_license"),
            "node_license": conflict.get("node_license"),
            "distance": conflict.get("distance"),
            "reason": conflict.get("reason"),
        },
        "source": source,
        "target": target,
        "reachable_before": reachable_before,
        "original_shortest_path": original_path,
        "original_distance": conflict.get("distance"),
        "graph_edges": len(pairs),
        "cut_count": len(cut_pairs),
        "cut_edges": cut_edges,
        "cut_edges_on_original_shortest_path": cut_on_shortest,
        "edge_disjoint_paths_count": len(flow_paths),
        "edge_disjoint_paths": flow_paths,
        "reachable_after": reachable_after,
        "residual_shortest_path": residual_path,
        "reachable_after_count": len(reachable_after_set),
        "verification": {
            "mincut_equals_maxflow": len(cut_pairs) == flow,
            "edge_disjoint_paths_equals_maxflow": len(flow_paths) == flow,
            "target_unreachable_after_removal": not reachable_after,
        },
    }
