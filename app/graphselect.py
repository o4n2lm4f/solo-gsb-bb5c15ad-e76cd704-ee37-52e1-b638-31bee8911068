"""全图许可证选定（只读）。

对一条**已保存审计**中的每个包，从其现有的许可证候选（SPDX OR 表达式或
多个并列条目解析出的候选集合；单许可证包候选只有一个，视为固定）中
**固定选定一个许可证**，沿 *使用方 -> 被依赖方* 的**全部可达关系**
（而非仅直接依赖边）逐条调用现有兼容矩阵（:mod:`app.licenses`），
求一份全图一致的选择。

结论分级：

* ``feasible`` —— 存在一份选择使**所有可达关系均兼容**（无硬冲突、无告警）；
* ``manual-review`` —— 不存在全兼容选择，但存在**避开全部硬冲突**的选择，
  残留关系全部为「需人工确认」（矩阵 warning），列出这些告警关系；
* ``unsolvable`` —— 任何选择都至少含一条硬冲突，给出无解结论，
  并给出（确定性的）硬冲突最少的选择与硬冲突关系清单；
* ``undetermined`` —— 审计含**未知许可证包**或**未解析依赖**，
  这些包/关系明确标为未判定：已知子图仍给出判定（``judged_outcome``），
  但不能声称全图可行。若已知子图本身无解（硬冲突不会因后续补全而消失），
  结论仍为 ``unsolvable``，同时保留未判定清单。

求解是有向关系上的有限域约束满足问题（CSP）：变量=包，域=候选许可证，
约束=全部可达 祖先包 -> 被依赖包 关系的兼容矩阵判定。求解为确定性两阶段
回溯搜索（MRV 选变量、候选声明顺序选值、增量前向检查）：先以 (0,0) 为界
判定全兼容方案是否存在；不存在时再按 (硬冲突数, 告警数) 字典序分支限界，
返回硬冲突最少（并列再告警最少）的确定性选择。整个计算纯内存只读：
不创建审计、不改动原审计结果与复核标记；原生 manifest 与 CycloneDX
审计均可直接使用。
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from . import licenses as lic

KIND = "graph-license-selection"

DIRECTION = "依赖边方向：使用方 -> 被依赖方；沿全部可达关系（传递闭包）调用兼容矩阵。"

METHOD = (
    "每个包在其现有 OR/并列候选中固定选一个许可证（单许可证视为固定），"
    "对 使用方→被依赖方 的全部可达关系逐条调用兼容矩阵；"
    "用确定性两阶段回溯搜索（MRV、增量前向检查、可加硬冲突下界）"
    "按 (硬冲突数, 告警数) 字典序求最优全图选择："
    "(0,0) 为全图可行，硬冲突为 0 但仍有告警为需人工确认，"
    "硬冲突无法降为 0 为无解；未知许可证包与未解析依赖不参与选择，标为未判定。"
)

# 结论状态
FEASIBLE = "feasible"
MANUAL_REVIEW = "manual-review"
UNSOLVABLE = "unsolvable"
UNDETERMINED = "undetermined"

# 每包选择状态
SEL_SELECTED = "selected"
SEL_UNKNOWN = "unknown-license"

# 回溯搜索的预算：节点数与墙钟秒数（任一超出即标记 search_truncated，
# 不强行给出无解结论；典型审计远在此预算内）。
_SEARCH_BUDGET = 200_000
_SEARCH_TIME_BUDGET = 5.0


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
        "unresolved": summary.get("unresolved"),
    }


# --- 图与候选域 ---------------------------------------------------------------


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


def _adjacency(pairs: List[Tuple[str, str]]) -> Dict[str, List[str]]:
    adjacency: Dict[str, List[str]] = {}
    for source, target in pairs:
        adjacency.setdefault(source, []).append(target)
        adjacency.setdefault(target, [])
    return adjacency


def _candidate_entries(node: Dict[str, Any]) -> List[Dict[str, str]]:
    """取节点候选许可证的富信息列表（矩阵内标识 + 展示 + 分类）。"""
    entries: List[Dict[str, str]] = []
    raw_entries = node.get("license_candidates") or []
    for item in raw_entries:
        token = item.get("token")
        if token is None:
            continue
        entries.append(
            {
                "token": str(token),
                "display": str(item.get("display") or token),
                "category": str(item.get("category") or lic.CATEGORIES.get(token, lic.UNKNOWN)),
                "category_label": str(
                    item.get("category_label")
                    or lic.CATEGORY_LABELS.get(
                        lic.CATEGORIES.get(token, lic.UNKNOWN), ""
                    )
                ),
            }
        )
    if not entries:
        # 兜底：用 license_tokens 重新规范化（旧数据/缺字段时）
        for token in node.get("license_tokens") or [node.get("license")]:
            info = lic.license_info(token)
            entries.append(
                {
                    "token": str(info["token"]),
                    "display": str(info["display"]),
                    "category": str(info["category"]),
                    "category_label": str(info["category_label"]),
                }
            )
    # 按 token 去重（保持声明顺序）
    unique: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for entry in entries:
        if entry["token"] not in seen:
            seen.add(entry["token"])
            unique.append(entry)
    return unique


def _bfs_paths(
    adjacency: Dict[str, List[str]],
    start: str,
    node_order: List[str],
) -> Dict[str, List[str]]:
    """从 start 沿 使用方→被依赖方 边做 BFS，返回 {可达节点: 最短路径}（不含 start）。

    邻接顺序与节点顺序均按审计声明顺序，BFS 唯一前驱使路径确定（环安全）。
    """
    parents: Dict[str, Optional[str]] = {start: None}
    queue: deque[str] = deque([start])
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, []):
            if nxt in parents:
                continue
            parents[nxt] = current
            queue.append(nxt)
    paths: Dict[str, List[str]] = {}
    for nid in node_order:
        if nid == start or nid not in parents:
            continue
        path = [nid]
        cur: Optional[str] = nid
        while cur != start:
            cur = parents.get(cur)
            if cur is None:
                break
            path.append(cur)
        path.reverse()
        paths[nid] = path
    return paths


# --- 回溯搜索（CSP：变量=包，域=候选许可证） -----------------------------------


# 搜索阶段：先用 (0,0) 界证伪/找到全兼容方案；找不到再放开为字典序最优
_PHASE_FEASIBILITY = "feasibility"
_PHASE_OPTIMIZE = "optimize"


class _Searcher:
    """对已知许可证包做确定性分支限界回溯。

    目标按字典序最小化 ``(硬冲突数, 告警数)``：
    (0,0) 即全图可行；(0, w>0) 即可避开硬冲突但需人工确认；(c>0, w) 即无解。

    分两阶段，避免可行解被“晚发现”拖垮：

    1. **可行性阶段**：界固定为 (0,0)（任何已产生冲突/告警的部分赋值立即剪枝），
       用 MRV + 增量前向检查快速判定全兼容方案是否存在；
    2. **优化阶段**：仅当可行性失败时运行，放开界并在搜索中按
       ``(硬冲突数, 告警数)`` 字典序收紧，返回硬冲突最少（并列再告警最少）的
       确定性选择，用于「需人工确认」与「无解」结论。

    增量维护每个未赋值变量在当前界下仍可取的候选数 ``feasible_count``：
    一次赋值只会改变与该变量有约束关系的邻居的计数，故 MRV 选变量为 O(V)、
    前向检查为 O(1)（维护空候选变量数）。
    """

    def __init__(
        self,
        order: List[str],
        domains: Dict[str, List[str]],
        relations: List[Dict[str, Any]],
    ) -> None:
        self.order = order
        self.domains = domains
        # 邻接约束：var -> [{"other": 另一端, "as": "u"|"v"（var 在约束中的角色）,
        #                  "constraint": 约束对象}]
        self.neighbors: Dict[str, List[Dict[str, Any]]] = {nid: [] for nid in order}
        # 两端无论怎么选都为冲突的关系（优化阶段的必然硬冲突下界用）
        self.forced_conflicts: Set[Tuple[str, str]] = set()
        for rel in relations:
            u = str(rel["ancestor"])
            v = str(rel["node"])
            pair_map: Dict[Tuple[str, str], Tuple[str, str]] = {}
            all_conflict = True
            for combo in rel["combinations"]:
                pair_map[(combo["parent"], combo["dep"])] = (
                    combo["status"],
                    combo["reason"],
                )
                if combo["status"] != lic.CONFLICT:
                    all_conflict = False
            constraint = {"u": u, "v": v, "map": pair_map}
            self.neighbors[v].append({"other": u, "as": "v", "constraint": constraint})
            self.neighbors[u].append({"other": v, "as": "u", "constraint": constraint})
            if all_conflict:
                self.forced_conflicts.add((u, v))

        self.assignment: Dict[str, str] = {}
        self.best_assignment: Optional[Dict[str, str]] = None
        self.best_conflicts: Optional[int] = None
        self.best_warnings: Optional[int] = None
        self.nodes_seen = 0
        self.truncated = False
        self._started_at = time.monotonic()

        # 未赋值变量 -> 各候选当前增量代价 (dc, dw)；初始无已赋值邻居，代价全 (0,0)
        self.deltas: Dict[str, Dict[str, Tuple[int, int]]] = {
            nid: {token: (0, 0) for token in domains[nid]} for nid in order
        }
        self.feasible_count: Dict[str, int] = {nid: len(domains[nid]) for nid in order}
        self.empty_domains = 0

    def _pair_status(self, constraint: Dict[str, Any], var_role: str,
                     var_token: str, other_token: str) -> str:
        if var_role == "u":
            return constraint["map"][(var_token, other_token)][0]
        return constraint["map"][(other_token, var_token)][0]

    def _within_bound(self, phase: str, conflicts: int, warnings: int) -> bool:
        if phase == _PHASE_FEASIBILITY:
            # 可行性阶段：界恒为 (0,0)，任何冲突/告警立即剪枝
            return conflicts == 0 and warnings == 0
        if self.best_conflicts is None:
            return True
        # 字典序 (冲突, 告警)：冲突数严格大于当前最优才剪；
        # 冲突数相同时仍可能靠更少告警改进（即使冲突 >0），必须保留。
        if conflicts > self.best_conflicts:
            return False
        if conflicts == self.best_conflicts and warnings >= (self.best_warnings or 0):
            return False
        return True

    def _is_feasible(self, phase: str, dc: int, dw: int,
                     cur_conflicts: int, cur_warnings: int) -> bool:
        return self._within_bound(phase, cur_conflicts + dc, cur_warnings + dw)

    def _recompute_neighbor(
        self, phase: str, nid: str, cur_conflicts: int, cur_warnings: int
    ) -> None:
        """赋值/撤销后按当前已赋值邻居重算 nid 各候选代价与可行计数。

        仅对**未赋值**变量维护计数；对仍在赋值中的变量调用为空操作
        （其候选代价不能在自身仍固定时被其他变量的撤销污染）。
        """
        if nid in self.assignment:
            return
        old_count = self.feasible_count[nid]
        new_deltas: Dict[str, Tuple[int, int]] = {}
        count = 0
        for token in self.domains[nid]:
            dc, dw = 0, 0
            for item in self.neighbors[nid]:
                other = item["other"]
                if other not in self.assignment:
                    continue
                status = self._pair_status(
                    item["constraint"], item["as"], token, self.assignment[other]
                )
                if status == lic.CONFLICT:
                    dc += 1
                elif status == lic.WARNING:
                    dw += 1
            new_deltas[token] = (dc, dw)
            if self._is_feasible(phase, dc, dw, cur_conflicts, cur_warnings):
                count += 1
        self.deltas[nid] = new_deltas
        self.feasible_count[nid] = count
        if old_count == 0 and count > 0:
            self.empty_domains -= 1
        elif old_count > 0 and count == 0:
            self.empty_domains += 1

    def _refresh_unassigned_bound(
        self, phase: str, cur_conflicts: int, cur_warnings: int
    ) -> None:
        """全局最优界收紧后，按新界重新统计所有未赋值变量的可行候选数。

        候选的增量代价（``deltas``）不变，只是界收紧后部分候选越界；
        同步维护空域变量计数 ``empty_domains``，供 MRV 与前向剪枝使用。
        """
        for nid in self.order:
            if nid in self.assignment:
                continue
            old_count = self.feasible_count[nid]
            count = sum(
                1
                for dc, dw in self.deltas[nid].values()
                if self._is_feasible(phase, dc, dw, cur_conflicts, cur_warnings)
            )
            self.feasible_count[nid] = count
            if old_count == 0 and count > 0:
                self.empty_domains -= 1
            elif old_count > 0 and count == 0:
                self.empty_domains += 1

    def _future_conflict_lb(self) -> int:
        """未决关系中必然带入的硬冲突数的可加 admissible 下界。

        只计入“至少一端未赋值”的关系：

        * 一端已固定、另一端未赋值：未赋值端取其各候选的**最少**新增冲突数；
        * 两端均未赋值：仅当无论双方如何选都冲突时计 1。

        对每个未赋值变量取其全部未决关系上的最少冲突数之和是合法的节点可加
        下界：每条关系至多在其某一端被计数一次（固定端侧不计），故不会重复，
        也不会超过真实最优值——用于优化阶段提前剪枝，低估不影响正确性。
        """
        total = len(
            [
                1
                for (u, v) in self.forced_conflicts
                if u not in self.assignment and v not in self.assignment
            ]
        )
        for nid in self.order:
            if nid in self.assignment:
                continue
            per_token_min: Optional[int] = None
            for dc, _dw in self.deltas[nid].values():
                # deltas 只含已固定端的代价；未固定端的 forced 冲突已在上面计过，
                # 这里每个变量单独加其“固定端侧不可避免冲突”，不重复。
                if per_token_min is None or dc < per_token_min:
                    per_token_min = dc
            if per_token_min:
                total += per_token_min
        return total

    def _reset_state(self) -> None:
        """两阶段之间重置增量搜索状态（约束/域不变）。"""
        self.assignment = {}
        self.deltas = {nid: {token: (0, 0) for token in self.domains[nid]} for nid in self.order}
        self.feasible_count = {nid: len(self.domains[nid]) for nid in self.order}
        self.empty_domains = 0

    def _pick_variable(self) -> Optional[str]:
        """MRV：可行候选最少的未赋值变量（并列按节点声明顺序）。"""
        best_var: Optional[str] = None
        best_count: Optional[int] = None
        for nid in self.order:
            if nid in self.assignment:
                continue
            count = self.feasible_count[nid]
            if count == 0:
                return nid  # 立即选它：其分支必被剪，快速失败回溯
            if best_count is None or count < best_count:
                best_count = count
                best_var = nid
        return best_var

    def _dfs(self, phase: str, cur_conflicts: int, cur_warnings: int) -> bool:
        """返回 True 表示已达成该阶段目标（可行性=(0,0)方案；优化=冲突已降为 0）。"""
        self.nodes_seen += 1
        if self.nodes_seen > _SEARCH_BUDGET or (
            time.monotonic() - self._started_at > _SEARCH_TIME_BUDGET
        ):
            self.truncated = True
            return False
        # 优化阶段：当前冲突 + 未决关系中不可避免的冲突下界若已不优于当前最优，剪枝
        if (
            phase == _PHASE_OPTIMIZE
            and self.best_conflicts is not None
            and cur_conflicts + self._future_conflict_lb() > self.best_conflicts
        ):
            return False
        if len(self.assignment) == len(self.order):
            if phase == _PHASE_FEASIBILITY:
                # 界恒为 (0,0)，到达完整赋值即全兼容方案：直接捕获（确定性的第一份）
                self.best_assignment = dict(self.assignment)
                self.best_conflicts = 0
                self.best_warnings = 0
                return True
            if self.best_conflicts is None or (
                cur_conflicts, cur_warnings
            ) < (self.best_conflicts, self.best_warnings or 0):
                self.best_assignment = dict(self.assignment)
                self.best_conflicts = cur_conflicts
                self.best_warnings = cur_warnings
            # 优化阶段找到 (0,0) 才是全局最优（可行性阶段已证伪时不会发生）；
            # 其余叶子（含 (0, w>0)）都要继续搜索字典序更优解，由界剪枝终止。
            return cur_conflicts == 0 and cur_warnings == 0

        var = self._pick_variable()
        if var is None:
            return False
        for token, (add_c, add_w) in self.deltas[var].items():
            new_c, new_w = cur_conflicts + add_c, cur_warnings + add_w
            # 候选本身已不可行（含被 MRV 选中的“空域”变量）：不赋值、不翻计数
            if not self._within_bound(phase, new_c, new_w):
                continue
            if self.feasible_count[var] == 0:
                self.empty_domains -= 1  # var 离开未赋值集合（按本次尝试前的当前计数）
            self.assignment[var] = token
            # 只有 var 的未赋值邻居的候选代价会变化
            touched = [
                item["other"]
                for item in self.neighbors[var]
                if item["other"] not in self.assignment
            ]
            for nid in dict.fromkeys(touched):
                self._recompute_neighbor(phase, nid, new_c, new_w)
            if self.empty_domains == 0 and self._dfs(phase, new_c, new_w):
                return True  # 可行性阶段：(0,0) 方案；优化阶段：冲突已为 0（即告警最优）
            # 撤销：先把 var 移出赋值，再统一按**父层界**重算 var 与其邻居。
            # 关键一：var 已撤销后，邻居重算不会把 var 当已固定端，var 自身重算
            # 也不会把自己的残留赋值算进候选代价；
            # 关键二：用父层 (cur_conflicts, cur_warnings) 作局部代价基准，
            # 但“是否可行”只取决于当前全局最优界 best（子树可能收紧过它）；
            # 关键三：子树收紧界后，**不相邻**未赋值变量的候选代价不变、却可能因
            # 新界变得不可行，故再全量刷新一次所有未赋值变量的可行计数，
            # 避免 MRV/空域剪枝沿用陈旧计数误杀父层兄弟分支。
            self.assignment.pop(var)
            for nid in dict.fromkeys([var] + touched):
                self._recompute_neighbor(phase, nid, cur_conflicts, cur_warnings)
            self._refresh_unassigned_bound(phase, cur_conflicts, cur_warnings)
        return False

    def solve(self) -> Dict[str, Any]:
        if self.order:
            # 阶段 1：界 (0,0) 的可行性判定；找到即在叶子捕获确定方案
            feasible_found = self._dfs(_PHASE_FEASIBILITY, 0, 0)
            # 阶段 2：仅在可行性搜索**完整跑完**且未找到时，放开界做字典序最优搜索；
            # 预算中断时不能证伪可行性，故不得给出「无解」结论。
            if not feasible_found and not self.truncated:
                self._reset_state()
                self._dfs(_PHASE_OPTIMIZE, 0, 0)
        return {
            "assignment": self.best_assignment or {},
            "conflicts": self.best_conflicts or 0,
            "warnings": self.best_warnings or 0,
            "search_nodes": self.nodes_seen,
            "truncated": self.truncated,
            "found": self.best_assignment is not None,
        }


# --- 主入口 ------------------------------------------------------------------


def select_graph_licenses(result: Dict[str, Any]) -> Dict[str, Any]:
    """对一份已保存审计结果求全图许可证选定，返回报告（纯只读，不改写输入）。"""
    nodes = result.get("nodes", []) or []
    node_order = [str(n.get("id")) for n in nodes]
    node_map = {str(n.get("id")): n for n in nodes}

    pairs = _edge_pairs(result)
    adjacency = _adjacency(pairs)

    # 1) 变量域：已知许可证包 -> 矩阵内候选（单候选即固定）；未知许可证包不参与选择
    domains: Dict[str, List[str]] = {}
    candidate_info: Dict[str, List[Dict[str, str]]] = {}
    known_ids: List[str] = []
    unknown_ids: List[str] = []
    for nid in node_order:
        node = node_map[nid]
        if node.get("license_known") is False:
            unknown_ids.append(nid)
            continue
        entries = _candidate_entries(node)
        tokens = [e["token"] for e in entries]
        if not tokens:
            unknown_ids.append(nid)
            continue
        domains[nid] = tokens
        candidate_info[nid] = entries
        known_ids.append(nid)

    # 2) 全部可达关系：对每个祖先做 BFS（与 analyzer 同一套邻接/路径口径）
    judged_relations: List[Dict[str, Any]] = []   # 两端均已知：进入 CSP
    undetermined_relations: List[Dict[str, Any]] = []
    for ancestor in node_order:
        paths = _bfs_paths(adjacency, ancestor, node_order)
        ancestor_known = ancestor in domains
        for dep, path in paths.items():
            dep_known = dep in domains
            base_rel = {
                "ancestor": ancestor,
                "node": dep,
                "distance": len(path) - 1,
                "path": path,
            }
            if ancestor_known and dep_known:
                judgment = lic.compatibility_candidates(domains[ancestor], domains[dep])
                judged_relations.append(
                    base_rel
                    | {
                        "combinations": judgment["combinations"],
                        "parent_candidates": judgment["parent_candidates"],
                        "dep_candidates": judgment["dep_candidates"],
                    }
                )
            else:
                undetermined_relations.append(
                    base_rel
                    | {
                        "kind": "unknown-license-relation",
                        "unknown_endpoint": "ancestor" if not ancestor_known else "node",
                        "reason": (
                            "祖先包 %s 的许可证未在兼容矩阵中识别，该可达关系无法自动判定。"
                            % ancestor
                            if not ancestor_known
                            else "被依赖包 %s 的许可证未在兼容矩阵中识别，该可达关系无法自动判定。"
                            % dep
                        ),
                    }
                )

    # 3) 未解析依赖：目标节点不存在，天然未判定（不进入 CSP）
    unresolved: List[Dict[str, Any]] = []
    for item in result.get("unresolved", []) or []:
        entry = {
            "kind": "unresolved-dependency",
            "source": str(item.get("source")),
            "reference": item.get("reference"),
            "reason": item.get("reason"),
            "path": None,
            "distance": None,
        }
        unresolved.append(entry)
        undetermined_relations.append(
            {
                "ancestor": str(item.get("source")),
                "node": str(item.get("reference")),
                "kind": "unresolved-dependency",
                "path": None,
                "distance": None,
                "reason": "未解析依赖 %s -> %s（%s），被依赖方未解析为现有包，无法判定。"
                % (item.get("source"), item.get("reference"), item.get("reason")),
            }
        )

    # 4) 回溯求全图最优选择
    started_at = time.monotonic()
    searcher = _Searcher(known_ids, domains, judged_relations)
    search = searcher.solve()
    elapsed_ms = round((time.monotonic() - started_at) * 1000)
    assignment: Dict[str, str] = search["assignment"]
    # 预算耗尽时，即便已得到一个启发式最优值，也未证明它是全局最优，
    # 不能据此声称「无解」或「需人工确认」，整体结论降为未判定。
    truncated = bool(search["truncated"])
    # 截断时的选择只供展示参考，不参与结论分级
    if truncated:
        assignment = dict(assignment)

    # 5) 按最终选择汇总每条已判定关系的结果
    final_conflicts: List[Dict[str, Any]] = []
    final_warnings: List[Dict[str, Any]] = []
    ok_count = 0
    for rel in judged_relations:
        u, v = str(rel["ancestor"]), str(rel["node"])
        tok_u = assignment.get(u)
        tok_v = assignment.get(v)
        status, reason = lic.OK, ""
        if tok_u is not None and tok_v is not None:
            status, reason = lic.compatibility(tok_u, tok_v)
        brief = {
            "ancestor": u,
            "node": v,
            "distance": rel["distance"],
            "path": rel["path"],
            "ancestor_selected": tok_u,
            "node_selected": tok_v,
            "status": status,
            "reason": reason,
        }
        if status == lic.CONFLICT:
            final_conflicts.append(brief)
        elif status == lic.WARNING:
            final_warnings.append(brief)
        else:
            ok_count += 1

    # 6) 已知子图结论（搜索被预算截断时不给出结论：未证明最优，也未证伪可行性）
    if truncated or not search["found"]:
        judged_outcome: Optional[str] = None
    elif search["conflicts"] > 0:
        judged_outcome = UNSOLVABLE
    elif search["warnings"] > 0:
        judged_outcome = MANUAL_REVIEW
    else:
        judged_outcome = FEASIBLE

    has_undetermined = bool(unknown_ids or unresolved)
    if truncated:
        # 搜索预算耗尽且未找到任何方案：不能声称无解也不能声称可行
        status = UNDETERMINED
    elif judged_outcome == UNSOLVABLE:
        # 已知节点间的硬冲突不会因未知部分日后补全而消失，无解结论成立
        status = UNSOLVABLE
    elif has_undetermined:
        status = UNDETERMINED
    elif judged_outcome == MANUAL_REVIEW:
        status = MANUAL_REVIEW
    else:
        status = FEASIBLE

    # 7) 每包选择明细
    selections: List[Dict[str, Any]] = []
    multi_count = 0
    for nid in node_order:
        node = node_map[nid]
        entries = candidate_info.get(nid, [])
        if nid in unknown_ids:
            selections.append(
                {
                    "node": _node_brief(node),
                    "fixed": False,
                    "selected_token": None,
                    "selected_display": None,
                    "selected_category": None,
                    "selected_category_label": None,
                    "status": SEL_UNKNOWN,
                    "reason": "许可证 %r 未在内置兼容矩阵中识别（或声明缺失），"
                    "无法从候选中固定选择，标记为未判定。" % node.get("license_display"),
                }
            )
            continue
        token = assignment.get(nid)
        entry = next((e for e in entries if e["token"] == token), None)
        fixed = len(entries) == 1
        if len(entries) > 1:
            multi_count += 1
        selections.append(
            {
                "node": _node_brief(node),
                "fixed": fixed,
                "selected_token": token,
                "selected_display": entry["display"] if entry else token,
                "selected_category": entry["category"] if entry else None,
                "selected_category_label": entry["category_label"] if entry else None,
                "status": SEL_SELECTED,
                "reason": (
                    "该包只声明了一个矩阵内许可证，选择固定。"
                    if fixed
                    else "该包声明了 %d 个 OR/并列候选，按全图一致方案选定 %s。"
                    % (len(entries), token)
                ),
            }
        )

    reachable_total = len(judged_relations) + len(
        [r for r in undetermined_relations if r.get("kind") == "unknown-license-relation"]
    )
    summary = {
        "packages": len(node_order),
        "known_packages": len(known_ids),
        "unknown_license_packages": len(unknown_ids),
        "multi_license_packages": multi_count,
        "fixed_single_license_packages": len(known_ids) - multi_count,
        "edges": len(pairs),
        "reachable_relations": reachable_total,
        "unresolved_dependencies": len(unresolved),
        "relations_total": reachable_total + len(unresolved),
        "relations_ok": ok_count,
        "relations_warning": len(final_warnings),
        "relations_conflict": len(final_conflicts),
        "relations_undetermined": len(undetermined_relations),
        "hard_conflicts": len(final_conflicts),
        "warnings": len(final_warnings),
        "undetermined_packages": len(unknown_ids),
        "undetermined_relations": len(undetermined_relations),
        "all_relations_compatible": status == FEASIBLE,
        "avoids_hard_conflicts": status in (FEASIBLE, MANUAL_REVIEW),
        "fully_determined": not has_undetermined and not truncated,
        "search_nodes": search["search_nodes"],
        "search_truncated": truncated,
        "search_budget": _SEARCH_BUDGET,
        "search_time_budget_seconds": _SEARCH_TIME_BUDGET,
        "search_elapsed_ms": elapsed_ms,
    }

    return {
        "kind": KIND,
        "read_only": True,
        "deterministic": True,
        "direction": DIRECTION,
        "method": METHOD,
        "audit": _audit_meta(result),
        "status": status,
        "judged_outcome": judged_outcome,
        "has_undetermined": has_undetermined,
        "conclusion": _conclusion(
            status, judged_outcome, summary, unknown_ids, unresolved, truncated
        ),
        "summary": summary,
        "selections": selections,
        "hard_conflict_relations": final_conflicts,
        "warning_relations": final_warnings,
        "undetermined_relations": undetermined_relations,
        "unresolved_dependencies": unresolved,
        "unknown_license_packages": [_node_brief(node_map[nid]) for nid in unknown_ids],
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


def _conclusion(
    status: str,
    judged_outcome: Optional[str],
    summary: Dict[str, Any],
    unknown_ids: List[str],
    unresolved: List[Dict[str, Any]],
    truncated: bool,
) -> str:
    judged_text = {
        FEASIBLE: "已知许可证部分存在所有关系均兼容的选择",
        MANUAL_REVIEW: "已知许可证部分只能避开硬冲突、仍含 %d 条需人工确认关系"
        % summary["relations_warning"],
        UNSOLVABLE: "已知许可证部分的任何选择都含 %d 条硬冲突，无全图可行解"
        % summary["relations_conflict"],
    }

    causes: List[str] = []
    if unknown_ids:
        causes.append("%d 个包许可证未知" % len(unknown_ids))
    if unresolved:
        causes.append("%d 条未解析依赖" % len(unresolved))

    if status == FEASIBLE:
        return (
            "全图一致选择存在：%d 个包的选择固定后，%d 条可达使用方→被依赖方关系"
            "全部与兼容矩阵兼容（硬冲突 0、需人工确认 0），无需人工确认。"
            % (summary["packages"], summary["relations_total"])
        )
    if status == MANUAL_REVIEW:
        return (
            "无法让所有关系兼容，但可避开全部硬冲突：推荐选择下仍有 %d 条关系为"
            "「需人工确认」（矩阵 warning，见告警关系清单），请法务逐条确认后再采用；"
            "硬冲突关系为 0。" % summary["relations_warning"]
        )
    if status == UNSOLVABLE:
        text = (
            "无解：%d 个包的全部候选组合中，不存在能避开硬冲突的全图选择；"
            "硬冲突最少的选择仍含 %d 条硬冲突（另有 %d 条需人工确认关系）。"
            % (summary["known_packages"], summary["relations_conflict"],
               summary["relations_warning"])
        )
        if causes:
            text += "另存在%s（已列为未判定），但不影响上述无解结论。" % "、".join(causes)
        return text
    # undetermined
    if truncated:
        return (
            "未判定：回溯搜索超过预算（节点 %d / 时长 %g 秒）仍未取得可证明最优的完整选择，"
            "不能给出可行或无解结论；其他未判定项：%s。请缩小候选范围后重试。"
            % (
                summary["search_budget"],
                summary["search_time_budget_seconds"],
                "、".join(causes) or "无",
            )
        )
    if judged_outcome is None:
        return (
            "未判定：%s，未对任何可达关系做矩阵判定，不能声称全图可行。"
            % "、".join(causes)
        )
    return (
        "未判定：%s；但审计存在%s，相关包与关系已标为未判定，"
        "在补全许可证声明或解析依赖之前，不能声称全图可行。"
        % (judged_text.get(judged_outcome, ""), "、".join(causes))
    )
