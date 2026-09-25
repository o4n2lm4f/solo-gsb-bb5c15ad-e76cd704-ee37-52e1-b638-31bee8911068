"""全图许可证选定（只读）。

对一条已保存的审计，把每个包节点的许可证固定下来：单许可证包只有其
矩阵内规范标识一个选择；声明了多个候选许可证的包（SPDX OR 表达式或多个
并列许可证条目）从候选集合中选定一个。随后沿 *使用方 -> 被依赖方* 的
**全部可达关系**（每个祖先到其每个可达后代，含传递关系与依赖环；
与分析器 BFS 的可达范围一致）逐一调用现有兼容矩阵
（:func:`licenses.compatibility`），求一份全图一致的许可证选择。

三级结论（``conclusion``）：

* ``compatible`` —— 存在一份选择使所有已判定关系均兼容（且图中不存在
  未知许可证或未解析依赖，否则不能声称全图可行，降级为需人工确认）；
* ``needs_confirmation`` —— 找不到“全部兼容”的选择，但存在一份选择可
  避开全部硬冲突（关系中只剩需人工确认项），或虽有全兼容选择但图中含
  未判定因素（未知许可证 / 未解析依赖）。返回该选择并列出告警关系与
  未判定项；
* ``unsolvable`` —— 任何选择都至少含一条硬冲突：给出无解结论，并返回
  硬冲突数最少的选择及无法避开的硬冲突关系。

未知许可证（含未声明许可证、矩阵外标识、无法拆分的复杂表达式）与
未解析依赖不参与求解，一律明确标为 ``undetermined``（未判定），
绝不据此声称全图可行。

求解是带前向校验的确定性回溯 CSP（MRV + 声明顺序决断），
分支预算耗尽时返回 ``truncated`` 并明确标注搜索不完整，不臆造结论。
整个计算纯内存只读：不创建审计、不改动复核标记；
原生 manifest 与 CycloneDX 审计结果结构一致，均可直接选定。
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from . import licenses as lic

KIND = "graph-wide-license-selection"

DIRECTION = "依赖边方向：使用方 -> 被依赖方；沿全部可达关系（含传递）调用兼容矩阵。"

# 三级结论
COMPATIBLE = "compatible"
NEEDS_CONFIRMATION = "needs_confirmation"
UNSOLVABLE = "unsolvable"

CONCLUSION_LABELS: Dict[str, str] = {
    COMPATIBLE: "全图兼容",
    NEEDS_CONFIRMATION: "需人工确认",
    UNSOLVABLE: "无解（任何选择都含硬冲突）",
}

# 关系经最终选择判定后可能出现的状态（ok/warning/conflict 沿用 licenses 模块
# 的矩阵状态常量；undetermined 为本模块因未知许可证而无法判定的关系）
REL_UNDETERMINED = "undetermined"

# 回溯搜索的节点（赋值）预算：超过即放弃精确解并明确标注搜索不完整。
# 许可证候选通常很少（OR 集合个位数），真实审计在此预算内必然搜完；
# 该上限仅为防御性保护。
DEFAULT_SEARCH_BUDGET = 200_000


# --- 图与候选 ---------------------------------------------------------------


def _adjacency(result: Dict[str, Any]) -> Tuple[Dict[str, List[str]], List[str]]:
    """构建邻接表（按审计边声明顺序，保证 BFS/求解结果确定），并返回节点顺序。"""
    nodes = result.get("nodes", []) or []
    order = [str(n.get("id")) for n in nodes]
    order_set = set(order)
    adjacency: Dict[str, List[str]] = {nid: [] for nid in order}
    seen: Set[Tuple[str, str]] = set()
    for edge in result.get("edges", []) or []:
        source = str(edge.get("source"))
        target = str(edge.get("target"))
        # 只保留连接已保存节点的边；未解析依赖没有目标节点，单独报告
        if source not in order_set or target not in order_set:
            continue
        key = (source, target)
        if key in seen:
            continue
        seen.add(key)
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])
    return adjacency, order


def _reachable_map(
    adjacency: Dict[str, List[str]], order: List[str]
) -> Dict[str, Dict[str, int]]:
    """对每个节点做 BFS，返回 {祖先: {可达后代: 最短跳数}}（不含祖先自身；天然处理环）。"""
    reach: Dict[str, Dict[str, int]] = {}
    for ancestor in order:
        distance = {ancestor: 0}
        queue: deque[str] = deque([ancestor])
        while queue:
            current = queue.popleft()
            for nxt in adjacency.get(current, []):
                if nxt not in distance:
                    distance[nxt] = distance[current] + 1
                    queue.append(nxt)
        distance.pop(ancestor, None)
        reach[ancestor] = distance
    return reach


def _node_known_candidates(node: Dict[str, Any]) -> List[str]:
    """取节点可选的矩阵内许可证 token；未知节点（含 UNLICENSED / 矩阵外）返回空表。"""
    if not node.get("license_known", False):
        return []
    tokens = node.get("license_tokens")
    if isinstance(tokens, list) and tokens:
        # 只接受矩阵内已知标识（多候选在解析时已保证全部已知，这里做兜底）
        return [str(t) for t in tokens if str(t) in lic.CATEGORIES]
    token = node.get("license")
    return [str(token)] if token and str(token) in lic.CATEGORIES else []


# --- 约束求解 ---------------------------------------------------------------


def _status_lookup() -> Dict[Any, Any]:
    """惰性求值的 (父包, 父许可证, 依赖包, 依赖许可证) -> 矩阵状态表。

    只在求解真正查询某对许可证时调用兼容矩阵，避免对 V 个节点预计算 O(V²)
    个无用格子（真实求解只触及候选 × 可达邻居相关的组合）。
    """

    class _Lookup(dict):
        def __missing__(self, key: Tuple[str, str, str, str]) -> str:
            parent, parent_token, dep, dep_token = key
            status, _reason = lic.compatibility(parent_token, dep_token)
            self[key] = status
            return status

    return _Lookup()


def _constraint_neighbors(
    constraints: List[Tuple[str, str]],
) -> Dict[str, List[Tuple[str, bool]]]:
    """把约束关系拆成按变量索引的邻接表：{变量: [(对方变量, 本变量是否为祖先), …]}。

    令回溯时单变量的合法性检查只扫其可达关系，而非全部 O(V²) 关系。
    """
    neighbors: Dict[str, List[Tuple[str, bool]]] = {}
    for parent, dep in constraints:
        neighbors.setdefault(parent, []).append((dep, True))
        neighbors.setdefault(dep, []).append((parent, False))
    return neighbors


def _relation_status(
    matrix: Dict[Tuple[str, str, str, str], str],
    var: str,
    value: str,
    other: str,
    other_value: str,
    var_is_parent: bool,
) -> str:
    """取 (本变量许可证, 对方许可证) 在矩阵中的状态，方向按本变量是否为祖先。"""
    if var_is_parent:
        return matrix[(var, value, other, other_value)]
    return matrix[(other, other_value, var, value)]


def _solve_zero_conflict(
    variables: List[str],
    domains: Dict[str, List[str]],
    constraints: List[Tuple[str, str]],
    matrix: Dict[Tuple[str, str, str, str], str],
    allowed: Set[str],
    budget: int,
) -> Tuple[Optional[Dict[str, str]], int, bool]:
    """回溯求一份使所有约束关系状态 ∈ ``allowed``（不含硬冲突）的赋值。

    MRV（存活候选最少的未赋值变量）+ 声明顺序决断；增量前向校验
    （support-count：记录每个候选值得到多少个已赋值邻居支持，归零即剪枝），
    令单次赋值的传播量只与受影响关系相关，而非重扫全部关系。
    返回 ``(赋值或 None, 已展开节点数, 是否因预算截断)``。
    """
    expansions = 0
    neighbors = _constraint_neighbors(constraints)
    index_of = {var: i for i, var in enumerate(variables)}
    # 每个候选值当前是否“存活”：存活 <=> 与所有已赋值可达节点相容。
    # 删除按回溯层级记录（deleted），回退时逐条恢复即可——被更早赋值杀死的
    # 候选在更深层已是死值（跳过），回退到该层时更深赋值均已撤销，恢复即正确。
    live: Dict[str, Dict[str, bool]] = {
        var: {value: True for value in domains[var]} for var in variables
    }
    assigned: Dict[str, str] = {}

    def propagate(var: str, value: str) -> Optional[List[Tuple[str, str]]]:
        """把 var=value 的约束传播给所有未赋值可达邻居；出现死域则返回 None。

        成功时返回本层新杀死的 ``(邻居, 候选值)`` 列表，供回溯恢复。
        """
        deleted: List[Tuple[str, str]] = []
        for other, is_parent in neighbors.get(var, ()):
            if other in assigned:
                continue
            for other_value in domains[other]:
                if not live[other][other_value]:
                    continue  # 已被更早赋值杀死，不计入本层删除
                if (
                    _relation_status(
                        matrix, other, other_value, var, value, not is_parent
                    )
                    not in allowed
                ):
                    live[other][other_value] = False
                    deleted.append((other, other_value))
            if not any(live[other].values()):
                return None
        return deleted

    def backtrack() -> bool:
        nonlocal expansions
        if len(assigned) == len(variables):
            return True
        expansions += 1
        if expansions > budget:
            raise _BudgetExhausted

        # MRV：存活候选最少的未赋值变量；并列按声明顺序（结果确定）
        var = min(
            (v for v in variables if v not in assigned),
            key=lambda v: (
                sum(1 for value in domains[v] if live[v][value]),
                index_of[v],
            ),
        )
        for value in domains[var]:
            if not live[var][value]:
                continue
            deleted = propagate(var, value)
            if deleted is None:
                continue
            assigned[var] = value
            if backtrack():
                return True
            del assigned[var]
            for other, other_value in deleted:
                live[other][other_value] = True
        return False

    try:
        found = backtrack()
    except _BudgetExhausted:
        return None, expansions, True
    return (dict(assigned) if found else None), expansions, False


class _BudgetExhausted(Exception):
    pass


def _solve_minimize_conflicts(
    variables: List[str],
    domains: Dict[str, List[str]],
    constraints: List[Tuple[str, str]],
    matrix: Dict[Tuple[str, str, str, str], str],
    budget: int,
) -> Tuple[Dict[str, str], int, int, bool]:
    """求硬冲突数最少的完整赋值（分支限界），返回 (赋值, 硬冲突数, 展开数, 截断)。

    变量按声明顺序赋值，候选按声明顺序尝试——首个达到最终最优值的解
    即“声明顺序上最早”的确定性最优解。增量计算当前前缀新增的硬冲突，
    并用“当前冲突数已不小于已知最优”剪枝。
    """
    expansions = 0
    best_assignment: Optional[Dict[str, str]] = None
    best_cost_value = len(constraints) + 1
    truncated = False
    assignment: Dict[str, str] = {}
    neighbors = _constraint_neighbors(constraints)

    def added_cost(var: str, value: str) -> int:
        cost = 0
        for other, is_parent in neighbors.get(var, ()):
            if other in assignment:
                if _relation_status(
                    matrix, var, value, other, assignment[other], is_parent
                ) == lic.CONFLICT:
                    cost += 1
        return cost

    def backtrack(index: int, current_cost: int) -> None:
        nonlocal expansions, best_assignment, best_cost_value, truncated
        if current_cost >= best_cost_value:
            return  # 不可能更优（相同也不要：保留声明顺序上更早的解）
        if index == len(variables):
            best_cost_value = current_cost
            best_assignment = dict(assignment)
            return
        expansions += 1
        if expansions > budget:
            truncated = True
            return
        var = variables[index]
        for value in domains[var]:
            assignment[var] = value
            backtrack(index + 1, current_cost + added_cost(var, value))
            del assignment[var]
            if best_cost_value == 0:
                return  # 已找到零冲突解，无需再试
            if truncated:
                return

    backtrack(0, 0)
    if best_assignment is None:
        # 仅在预算小到连第一层都未完成时发生：用各节点首个候选兜底给出一份赋值
        best_assignment = {var: domains[var][0] for var in variables}
        best_cost_value = _count_conflicts(best_assignment, constraints, matrix)
    return best_assignment, best_cost_value, expansions, truncated


def _count_conflicts(
    assignment: Dict[str, str],
    constraints: List[Tuple[str, str]],
    matrix: Dict[Tuple[str, str, str, str], str],
) -> int:
    return sum(
        1
        for parent, dep in constraints
        if matrix[(parent, assignment[parent], dep, assignment[dep])] == lic.CONFLICT
    )


# --- 报告组装 ---------------------------------------------------------------


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


def _selection_entry(node: Dict[str, Any]) -> Dict[str, Any]:
    nid = str(node.get("id"))
    candidates = _node_known_candidates(node)
    multi = bool(node.get("license_multi", False))
    if candidates:
        return {
            "id": nid,
            "name": node.get("name"),
            "version": node.get("version"),
            "version_unspecified": node.get("version_unspecified", False),
            "license_display": node.get("license_display"),
            "license_category": node.get("license_category"),
            "license_multi": multi,
            "candidates": candidates,
            "selected_license": None,  # 由求解结果回填
            "selected_from": "candidate" if multi else "single",
            "fixed": len(candidates) == 1 and not multi,
            "undetermined": False,
            "undetermined_reason": None,
        }
    # 未知许可证：不在矩阵中，不能选定
    reason = "节点许可证未在兼容矩阵中识别"
    if not str(node.get("license_raw") or "").strip():
        reason = "节点未声明许可证（UNLICENSED）"
    return {
        "id": nid,
        "name": node.get("name"),
        "version": node.get("version"),
        "version_unspecified": node.get("version_unspecified", False),
        "license_display": node.get("license_display"),
        "license_category": node.get("license_category"),
        "license_multi": multi,
        "candidates": [],
        "selected_license": None,
        "selected_from": "undetermined",
        "fixed": False,
        "undetermined": True,
        "undetermined_reason": reason,
    }


def _relation_entry(
    ancestor: str,
    descendant: str,
    distance: int,
    direct: bool,
    assignment: Dict[str, str],
    known: Set[str],
    matrix: Dict[Tuple[str, str, str, str], str],
    node_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """按最终选择评估单条 祖先 -> 后代 可达关系（含逐矩阵理由）。"""
    entry: Dict[str, Any] = {
        "ancestor": ancestor,
        "node": descendant,
        "distance": distance,
        "direct": direct,
        "shortest_path": [],
    }
    if ancestor in known and descendant in known:
        parent_token = assignment[ancestor]
        dep_token = assignment[descendant]
        status = matrix[(ancestor, parent_token, descendant, dep_token)]
        _, reason = lic.compatibility(parent_token, dep_token)
        entry.update(
            {
                "status": status,
                "ancestor_license": parent_token,
                "node_license": dep_token,
                "reason": reason,
                "undetermined": False,
            }
        )
    else:
        unknown_parts = []
        if ancestor not in known:
            unknown_parts.append("祖先 %s" % ancestor)
        if descendant not in known:
            unknown_parts.append("被依赖方 %s" % descendant)
        # 已知端显示最终选定的许可证 token，未知端只能保留原文展示
        entry.update(
            {
                "status": REL_UNDETERMINED,
                "ancestor_license": assignment.get(ancestor)
                if ancestor in known
                else node_map[ancestor].get("license_display"),
                "node_license": assignment.get(descendant)
                if descendant in known
                else node_map[descendant].get("license_display"),
                "reason": "涉及未在兼容矩阵中识别的许可证（%s），无法自动判定，标记为未判定。"
                % "、".join(unknown_parts),
                "undetermined": True,
            }
        )
    return entry


def _shortest_paths(
    adjacency: Dict[str, List[str]],
    flagged_pairs: Set[Tuple[str, str]],
) -> Dict[Tuple[str, str], List[str]]:
    """对需要展示的 (祖先, 后代) 对批量求 BFS 最短路径（结果确定）。"""
    pairs_by_source: Dict[str, List[str]] = {}
    for ancestor, descendant in flagged_pairs:
        pairs_by_source.setdefault(ancestor, []).append(descendant)
    paths: Dict[Tuple[str, str], List[str]] = {}
    for ancestor, targets in pairs_by_source.items():
        wanted = set(targets)
        parents: Dict[str, Optional[str]] = {ancestor: None}
        queue: deque[str] = deque([ancestor])
        while queue and wanted:
            current = queue.popleft()
            for nxt in adjacency.get(current, []):
                if nxt in parents:
                    continue
                parents[nxt] = current
                if nxt in wanted:
                    wanted.discard(nxt)
                queue.append(nxt)
        for descendant in targets:
            path: List[str] = []
            cur: Optional[str] = descendant
            while cur is not None:
                path.append(cur)
                cur = parents.get(cur) if cur != ancestor else None
            path.reverse()
            paths[(ancestor, descendant)] = path
    return paths


def select_graph_licenses(
    result: Dict[str, Any],
    search_budget: int = DEFAULT_SEARCH_BUDGET,
) -> Dict[str, Any]:
    """对一份审计结果做全图许可证选定，返回选定报告（只读，不改写输入）。"""
    nodes = result.get("nodes", []) or []
    node_map = {str(n.get("id")): n for n in nodes}
    adjacency, order = _adjacency(result)
    direct_edges: Set[Tuple[str, str]] = {
        (source, target)
        for source, targets in adjacency.items()
        for target in targets
    }
    reach = _reachable_map(adjacency, order)

    selections = [_selection_entry(node) for node in nodes]
    selection_by_id = {item["id"]: item for item in selections}

    known = {item["id"] for item in selections if not item["undetermined"]}
    unknown_ids = [nid for nid in order if nid not in known]
    variables = [nid for nid in order if nid in known]
    domains: Dict[str, List[str]] = {
        nid: selection_by_id[nid]["candidates"] for nid in variables
    }

    # 约束 = 两端节点都已知的全部可达关系（祖先, 后代）；含未知端的关系
    # 在最终评估时按未判定处理，不进入求解器
    constraints: List[Tuple[str, str]] = []
    for ancestor in order:
        for descendant in reach[ancestor]:
            if ancestor in known and descendant in known:
                constraints.append((ancestor, descendant))

    matrix = _status_lookup()

    # 1) 求全部关系兼容（只接受 ok）的选择
    all_ok, expand_ok, trunc_ok = _solve_zero_conflict(
        variables, domains, constraints, matrix, {lic.OK}, search_budget
    )
    # 2) 若没有，求可避开全部硬冲突（接受 ok / warning）的选择
    no_conflict: Optional[Dict[str, str]] = None
    expand_warn = 0
    trunc_warn = False
    if all_ok is None and not trunc_ok:
        no_conflict, expand_warn, trunc_warn = _solve_zero_conflict(
            variables,
            domains,
            constraints,
            matrix,
            {lic.OK, lic.WARNING},
            search_budget,
        )

    unresolved = result.get("unresolved", []) or []
    undetermined_factors = bool(unknown_ids or unresolved)

    search: Dict[str, Any]
    assignment: Dict[str, str]
    conclusion: str

    if all_ok is not None and not undetermined_factors:
        conclusion = COMPATIBLE
        assignment = all_ok
        search = {
            "stages": [
                {"stage": "all-compatible", "found": True, "expansions": expand_ok,
                 "truncated": trunc_ok},
            ],
            "budget": search_budget,
            "truncated": trunc_ok,
        }
    elif all_ok is not None:
        # 存在全兼容选择，但图中含未知许可证或未解析依赖：不能声称全图可行
        conclusion = NEEDS_CONFIRMATION
        assignment = all_ok
        search = {
            "stages": [
                {"stage": "all-compatible", "found": True, "expansions": expand_ok,
                 "truncated": trunc_ok},
            ],
            "budget": search_budget,
            "truncated": trunc_ok,
        }
    elif no_conflict is not None:
        # 只能避开硬冲突：剩余关系含需人工确认项
        conclusion = NEEDS_CONFIRMATION
        assignment = no_conflict
        search = {
            "stages": [
                {"stage": "all-compatible", "found": False, "expansions": expand_ok,
                 "truncated": trunc_ok},
                {"stage": "avoid-hard-conflict", "found": True, "expansions": expand_warn,
                 "truncated": trunc_warn},
            ],
            "budget": search_budget,
            "truncated": trunc_warn,
        }
    else:
        # 3) 精确求解未找到可避开硬冲突的选择（或前序搜索被预算截断）：
        #    求硬冲突最少的完整选择，再按最少硬冲突数给出结论
        best, best_cost, expand_min, trunc_min = _solve_minimize_conflicts(
            variables, domains, constraints, matrix, search_budget
        )
        assignment = best
        search = {
            "stages": [
                {"stage": "all-compatible", "found": False, "expansions": expand_ok,
                 "truncated": trunc_ok},
                {"stage": "avoid-hard-conflict",
                 "found": False if not trunc_warn else None,
                 "expansions": expand_warn, "truncated": trunc_warn},
                {"stage": "minimize-hard-conflict", "found": True,
                 "minimum_hard_conflicts": best_cost,
                 "expansions": expand_min, "truncated": trunc_min},
            ],
            "budget": search_budget,
            "truncated": trunc_ok or trunc_warn or trunc_min,
        }
        # 最少硬冲突为 0：存在避开全部硬冲突的选择（仅在搜索被预算截断时
        # 可能走到这里），结论为需人工确认，不能误判无解；大于 0 才是无解。
        conclusion = NEEDS_CONFIRMATION if best_cost == 0 else UNSOLVABLE

    # 回填每包选择
    for item in selections:
        if not item["undetermined"]:
            item["selected_license"] = assignment.get(item["id"])

    # 按最终选择评估全部可达关系
    relations: List[Dict[str, Any]] = []
    for ancestor in order:
        for descendant, distance in reach[ancestor].items():
            relations.append(
                _relation_entry(
                    ancestor,
                    descendant,
                    distance,
                    (ancestor, descendant) in direct_edges,
                    assignment,
                    known,
                    matrix,
                    node_map,
                )
            )

    warning_relations = [r for r in relations if r["status"] == lic.WARNING]
    conflict_relations = [r for r in relations if r["status"] == lic.CONFLICT]
    undetermined_relations = [r for r in relations if r["status"] == REL_UNDETERMINED]
    ok_relations = [r for r in relations if r["status"] == lic.OK]

    # 为需要展示的关系（非兼容）批量计算最短路径
    flagged_pairs = {
        (r["ancestor"], r["node"])
        for r in warning_relations + conflict_relations + undetermined_relations
    }
    paths = _shortest_paths(adjacency, flagged_pairs)
    for relation in warning_relations + conflict_relations + undetermined_relations:
        relation["shortest_path"] = paths.get(
            (relation["ancestor"], relation["node"]), []
        )

    summary = {
        "packages": len(order),
        "multi_license_packages": sum(1 for item in selections if item["license_multi"]),
        "decided_packages": len(variables),
        "undetermined_packages": len(unknown_ids),
        "reachable_relations": len(relations),
        "direct_relations": len(direct_edges),
        "transitive_relations": len(relations) - len(direct_edges),
        "ok_relations": len(ok_relations),
        "warning_relations": len(warning_relations),
        "hard_conflict_relations": len(conflict_relations),
        "undetermined_relations": len(undetermined_relations),
        "unresolved_dependencies": len(unresolved),
    }

    warnings_list: List[str] = []
    if unknown_ids:
        warnings_list.append(
            "存在 %d 个许可证未知/未声明的包（%s），不参与全图选定，"
            "相关关系标记为未判定；不能仅凭已判定关系声称全图可行。"
            % (len(unknown_ids), "、".join(unknown_ids[:10])
               + ("…" if len(unknown_ids) > 10 else ""))
        )
    if unresolved:
        warnings_list.append(
            "存在 %d 条未解析依赖（目标包未在审计节点中），无法纳入全图可达关系，"
            "标记为未判定：补齐依赖后需重新选定。" % len(unresolved)
        )
    if conclusion == NEEDS_CONFIRMATION and not conflict_relations:
        if warning_relations and undetermined_relations:
            warnings_list.append(
                "当前选择可避开全部硬冲突，但仍有 %d 条关系需人工确认、"
                "%d 条关系未判定。" % (len(warning_relations), len(undetermined_relations))
            )
        elif warning_relations:
            warnings_list.append(
                "当前选择可避开全部硬冲突，但仍有 %d 条关系为“需人工确认”"
                "（矩阵 warning，如专有授权 / 动态链接），不能判为全图兼容。"
                % len(warning_relations)
            )
        elif undetermined_relations:
            warnings_list.append(
                "已判定关系全部兼容，但 %d 条关系涉及未知许可证，未判定前"
                "不能声称全图可行。" % len(undetermined_relations)
            )
    if conclusion == UNSOLVABLE:
        warnings_list.append(
            "不存在能避开全部硬冲突的选择：最少仍有 %d 条可达关系为硬冲突，"
            "结论为无解；下列选择为硬冲突最少的方案，仅供定位冲突。"
            % len(conflict_relations)
        )
    if search["truncated"]:
        warnings_list.append(
            "回溯搜索在预算 %d 个赋值节点内未完成（分支过多），结论可能不精确；"
            "下列选择为当前找到的最优结果，硬冲突最少性未被完整证明。" % search_budget
        )

    return {
        "kind": KIND,
        "read_only": True,
        "direction": DIRECTION,
        "conclusion": conclusion,
        "conclusion_label": CONCLUSION_LABELS[conclusion],
        "audit": _audit_meta(result),
        "search": search,
        "summary": summary,
        "selections": selections,
        "relations": {
            "ok": ok_relations,
            "warnings": warning_relations,
            "hard_conflicts": conflict_relations,
            "undetermined": undetermined_relations,
        },
        "unresolved": [dict(item) for item in unresolved],
        "warnings": warnings_list,
    }
