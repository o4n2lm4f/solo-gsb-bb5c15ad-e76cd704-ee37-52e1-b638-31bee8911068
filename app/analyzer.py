"""manifest 解析、节点规范化与传递许可证约束分析。

支持的 manifest 结构（均为可选字段，可混用）::

    {
      "name": "my-app",
      "packages": [
        {"name": "web-app", "version": "1.0.0", "license": "MIT",
         "dependencies": [                          # 字符串或对象均可
           "lib-a",
           {"name": "lib-b", "version": "^2.0.0"},
           {"name": "utils", "version": "1.2.0", "license": "MIT"}
         ]},
        {"id": "lib-a@1.4.0", "name": "lib-a", "version": "1.4.0",
         "license": "Apache-2.0"}
      ],
      "dependencies": { "web-app@1.0.0": ["lib-a@1.4.0", ...] },
      "edges": [ {"source": "lib-a@1.4.0", "target": "utils@1.2.0"} ]
    }

顶层 ``packages`` 声明节点；``dependencies``（包内或顶层）与 ``edges``
声明依赖边。依赖边方向为 *使用方 -> 被依赖方*，传递约束沿边传播。

除上述原生格式外，也支持直接提交 CycloneDX JSON（SBOM）：带 ``bomFormat``
或 ``components`` 数组的输入会路由到 ``cyclonedx`` 模块解析（组件 bom-ref
映射为包节点、按 ref/dependsOn 还原依赖边），随后复用本模块的传递约束与
最短路径冲突分析。
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from . import licenses as lic

UNVERSIONED = "*"  # 未声明版本时的占位版本


# --- 基础规范化 -------------------------------------------------------------


def clean_version(raw: object) -> Tuple[str, bool]:
    """规范化版本字符串。

    仅去除常见范围前缀（^ ~ = >= <= > < v 与空白），不做 semver 解析，
    因为本工具做静态审计而非解析。返回 ``(版本, 是否未声明)``。
    """
    if raw is None:
        return UNVERSIONED, True
    text = str(raw).strip()
    if not text or text in ("*", "latest", "x", "X"):
        return UNVERSIONED, True
    cleaned = text.lstrip("^~=><vV").strip()
    # ">=1.2" 这种去掉前缀后以数字开头的也会自然清理；空串兜底
    return (cleaned or text), False


def node_id(name: str, version: str) -> str:
    return "%s@%s" % (name.strip().lower(), version)


def split_ref(ref: object) -> Optional[Tuple[str, str]]:
    """把 "name@version" / {"name":..,"version":..} 拆成 (name, version)。

    字符串按最后一个 @ 拆分（scoped 包如 @scope/pkg@1.0 也能处理）。
    """
    if isinstance(ref, dict):
        name = str(ref.get("name") or ref.get("id") or "").strip()
        if not name:
            return None
        version, _ = clean_version(ref.get("version"))
        return name.lower(), version
    text = str(ref).strip()
    if not text:
        return None
    if "@" in text and not text.startswith("@"):
        name, _, version = text.rpartition("@")
        return name.strip().lower(), version.strip() or UNVERSIONED
    if text.startswith("@") and text.count("@") >= 2:
        head, _, version = text.rpartition("@")
        return head.strip().lower(), version.strip() or UNVERSIONED
    return text.lower(), UNVERSIONED


def _add_warning(warnings: List[str], seen: Set[str], message: str) -> None:
    if message not in seen:
        seen.add(message)
        warnings.append(message)


def license_tokens(node: Dict[str, Any]) -> List[str]:
    """取节点的候选许可证 token 列表（多候选为多个矩阵标识，单许可证为一个）。"""
    tokens = node.get("license_tokens")
    if isinstance(tokens, list) and tokens:
        return [str(t) for t in tokens]
    token = node.get("license")
    return [str(token)] if token else []


def _node_from_info(
    nid: str,
    name: str,
    version: str,
    info: Dict[str, Any],
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """由许可证富信息字典构造审计节点（analyzer / cyclonedx 共用）。"""
    candidates = info.get("candidates") or [info]
    tokens = [str(item.get("token")) for item in candidates if item.get("known")]
    if not tokens:
        tokens = [str(info.get("token"))]
    node: Dict[str, Any] = {
        "id": nid,
        "name": name,
        "version": version,
        "version_unspecified": version == UNVERSIONED,
        "license_raw": info["raw"],
        "license_display": info["display"],
        "license": info["token"],
        "license_known": info["known"],
        "license_category": info["category"],
        "license_multi": bool(info.get("multi")),
        "license_candidates": [
            {
                "token": item.get("token"),
                "display": item.get("display"),
                "category": item.get("category"),
                "category_label": item.get("category_label"),
            }
            for item in candidates
        ],
        "license_tokens": tokens,
        "constraints": [],
        "conflict_count": 0,
    }
    if extra:
        node.update(extra)
    return node


# --- 解析 manifest ----------------------------------------------------------


def analyze_manifest(manifest: Any, manifest_name: str = "uploaded-manifest") -> Dict[str, Any]:
    """解析并审计 manifest，返回完整审计结果字典。"""
    warnings: List[str] = []
    warning_seen: Set[str] = set()
    warn = lambda msg: _add_warning(warnings, warning_seen, msg)

    if not isinstance(manifest, dict):
        return _empty_result(manifest_name) | {
            "status": "error",
            "error": "manifest 必须是 JSON 对象，包含 packages / dependencies / edges 等字段。",
            "warnings": warnings,
        }

    # CycloneDX BOM（bomFormat / components）走专门解析，复用本模块的分析与结果构建
    from . import cyclonedx  # 延迟导入，避免与 cyclonedx 模块循环依赖

    if cyclonedx.is_cyclonedx(manifest):
        return cyclonedx.analyze_bom(manifest, manifest_name)

    display_name = str(manifest.get("name") or manifest_name).strip() or manifest_name

    nodes: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    edges: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, str]] = []
    unresolved_seen: Set[Tuple[str, str]] = set()

    def register_package(pkg: Any) -> Optional[str]:
        if not isinstance(pkg, dict):
            warn("packages 中存在非对象条目，已跳过：%r" % (pkg,))
            return None
        name = str(pkg.get("name") or "").strip()
        if not name:
            pkg_id = str(pkg.get("id") or "").strip()
            if not pkg_id:
                warn("packages 中存在缺少 name 的条目，已跳过：%r" % (pkg,))
                return None
            parsed = split_ref(pkg_id)
            if not parsed:
                warn("packages 中存在无法解析的 id：%r" % (pkg_id,))
                return None
            name, version = parsed
        else:
            version, _ = clean_version(pkg.get("version"))
        nid = node_id(name, version)
        info = lic.parse_license_entries(pkg.get("license"))
        if nid in nodes:
            existing = nodes[nid]
            if existing["license_display"] != info["display"]:
                warn(
                    "包 %s 被重复声明且许可证不一致（%s vs %s），保留首次声明的 %s。"
                    % (nid, existing["license_display"], info["display"], existing["license_display"])
                )
            return nid
        nodes[nid] = _node_from_info(nid, name, version, info)
        order.append(nid)
        return nid

    def resolve_ref(ref: object, source_nid: str) -> Optional[str]:
        parsed = split_ref(ref)
        if not parsed:
            _mark_unresolved(unresolved, unresolved_seen, source_nid, str(ref), "引用无法解析")
            return None
        ref_name, ref_version = parsed
        # 依赖项内联声明（带 license 等字段）时注册为节点
        if isinstance(ref, dict) and (ref.get("license") is not None or "dependencies" in ref):
            inline = dict(ref)
            inline.setdefault("name", parsed[0])
            inline.setdefault("version", "" if ref_version == UNVERSIONED else ref_version)
            register_package(inline)
        if ref_version != UNVERSIONED:
            target = node_id(ref_name, ref_version)
            if target in nodes:
                return target
            _mark_unresolved(
                unresolved,
                unresolved_seen,
                source_nid,
                "%s@%s" % (ref_name, ref_version),
                "依赖的精确版本未在 packages 中声明",
            )
            return None
        # 只给了名字：唯一匹配则解析，多个匹配则要求消歧
        candidates = [n for n in order if nodes[n]["name"].lower() == ref_name]
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) == 0:
            _mark_unresolved(
                unresolved, unresolved_seen, source_nid, ref_name, "依赖包未在 packages 中声明"
            )
        else:
            _mark_unresolved(
                unresolved,
                unresolved_seen,
                source_nid,
                ref_name,
                "存在多个版本：%s，请用 name@version 消歧" % ", ".join(sorted(candidates)),
            )
        return None

    # 1) 注册所有显式包节点（两遍：先注册保证名字引用可解析）
    raw_packages = manifest.get("packages")
    if isinstance(raw_packages, list):
        for pkg in raw_packages:
            register_package(pkg)
    elif raw_packages is not None:
        warn("packages 字段不是数组，已忽略。")

    # 2) 包内 dependencies
    if isinstance(raw_packages, list):
        for pkg in raw_packages:
            if not isinstance(pkg, dict):
                continue
            source = register_package(pkg)  # 已注册则返回既有 id
            deps = pkg.get("dependencies")
            if deps is None:
                continue
            for ref in _iter_refs(deps):
                target = resolve_ref(ref, source or "?")
                if source and target and source != target:
                    edges.append(
                        {
                            "source": source,
                            "target": target,
                            "from": "package-dependencies",
                        }
                    )

    # 3) 顶层 dependencies（映射或数组形式）
    top_deps = manifest.get("dependencies")
    if top_deps is not None:
        if isinstance(top_deps, dict):
            for src_ref, targets in top_deps.items():
                source = resolve_ref(src_ref, "?")
                if not source:
                    continue
                for ref in _iter_refs(targets):
                    target = resolve_ref(ref, source)
                    if target and source != target:
                        edges.append({"source": source, "target": target, "from": "dependencies"})
        elif isinstance(top_deps, list):
            for entry in top_deps:
                if not isinstance(entry, dict):
                    continue
                source = resolve_ref(entry.get("source") or entry.get("from"), "?")
                target = resolve_ref(entry.get("target") or entry.get("to"), source or "?")
                if source and target and source != target:
                    edges.append({"source": source, "target": target, "from": "dependencies"})
        else:
            warn("顶层 dependencies 字段类型不支持，已忽略。")

    # 4) 显式 edges
    raw_edges = manifest.get("edges")
    if isinstance(raw_edges, list):
        for entry in raw_edges:
            if not isinstance(entry, dict):
                continue
            source = resolve_ref(entry.get("source") or entry.get("from"), "?")
            target = resolve_ref(entry.get("target") or entry.get("to"), source or "?")
            if source and target and source != target:
                edges.append(
                    {
                        "source": source,
                        "target": target,
                        "from": str(entry.get("type") or "edges"),
                    }
                )
    elif raw_edges is not None:
        warn("edges 字段不是数组，已忽略。")

    # 去重边（保留首次出现的来源）
    deduped_edges: List[Dict[str, Any]] = []
    seen_edges: Set[Tuple[str, str]] = set()
    for edge in edges:
        key = (edge["source"], edge["target"])
        if key not in seen_edges:
            seen_edges.add(key)
            deduped_edges.append(edge)

    return _build_result(display_name, manifest, nodes, order, deduped_edges, unresolved, warnings)


def _iter_refs(value: Any):
    """dependencies 支持数组，也支持 {name: version} 映射。"""
    if isinstance(value, list):
        yield from value
    elif isinstance(value, dict):
        for name, version in value.items():
            if isinstance(version, dict):
                item = dict(version)
                item.setdefault("name", name)
                yield item
            else:
                yield {"name": name, "version": version}
    elif isinstance(value, str):
        yield value


def _mark_unresolved(
    bucket: List[Dict[str, str]],
    seen: Set[Tuple[str, str]],
    source: str,
    ref: str,
    reason: str,
) -> None:
    key = (source, ref)
    if key not in seen:
        seen.add(key)
        bucket.append({"source": source, "reference": ref, "reason": reason})


# --- 传递约束 + 最短路径冲突 -------------------------------------------------


def _build_result(
    display_name: str,
    raw_manifest: Any,
    nodes: Dict[str, Dict[str, Any]],
    order: List[str],
    edges: List[Dict[str, Any]],
    unresolved: List[Dict[str, str]],
    parse_warnings: List[str],
) -> Dict[str, Any]:
    adjacency: Dict[str, List[str]] = {nid: [] for nid in order}
    for edge in edges:
        adjacency[edge["source"]].append(edge["target"])

    conflicts: List[Dict[str, Any]] = []

    # 对每个节点做 BFS：沿依赖边传播祖先许可证约束。
    # BFS 首次到达即为最短依赖路径；对同一祖先只在首次到达处判定一次。
    for ancestor in order:
        parents: Dict[str, Optional[str]] = {ancestor: None}
        visited_ancestors: Set[str] = {ancestor}
        queue: deque[str] = deque([ancestor])
        while queue:
            current = queue.popleft()
            for nxt in adjacency.get(current, []):
                if nxt in parents:
                    continue  # BFS 已找到更短路径；同时天然处理环
                parents[nxt] = current
                if nxt not in visited_ancestors:
                    visited_ancestors.add(nxt)
                    queue.append(nxt)

                ancestor_node = nodes[ancestor]
                dep_node = nodes[nxt]
                judgment = lic.compatibility_candidates(
                    license_tokens(ancestor_node), license_tokens(dep_node)
                )
                status = judgment["status"]
                multi_pair = (
                    len(judgment["parent_candidates"]) > 1
                    or len(judgment["dep_candidates"]) > 1
                )
                if status != lic.OK:
                    path = _reconstruct_path(parents, ancestor, nxt)
                    conflict: Dict[str, Any] = {
                        "kind": "license-conflict",
                        "severity": "error" if status == lic.CONFLICT else "warning",
                        "status": status,
                        "ancestor": ancestor,
                        "node": nxt,
                        "ancestor_license": ancestor_node["license_display"],
                        "node_license": dep_node["license_display"],
                        "ancestor_multi": bool(ancestor_node.get("license_multi")),
                        "node_multi": bool(dep_node.get("license_multi")),
                        "distance": len(path) - 1,
                        "path": path,
                        "reason": judgment["reason"],
                    }
                    if multi_pair:
                        # 多候选：列出各候选组合的逐条判定，供网页与导出展示
                        conflict["candidate_combinations"] = judgment["combinations"]
                        conflict["combination_counts"] = {
                            "total": len(judgment["combinations"]),
                            "ok": sum(
                                1 for item in judgment["combinations"] if item["status"] == lic.OK
                            ),
                            "conflict": sum(
                                1
                                for item in judgment["combinations"]
                                if item["status"] == lic.CONFLICT
                            ),
                            "warning": sum(
                                1
                                for item in judgment["combinations"]
                                if item["status"] == lic.WARNING
                            ),
                        }
                    conflicts.append(conflict)
                if any(lic.imposes_constraint(token) for token in license_tokens(ancestor_node)):
                    nodes[nxt]["constraints"].append(
                        {
                            "from": ancestor,
                            "license": ancestor_node["license_display"],
                            "category": ancestor_node["license_category"],
                            "distance": _distance_to(parents, ancestor, nxt),
                            "status": status,
                        }
                    )

    # 约束按距离排序，冲突排序：错误优先 -> 距离短 -> 名字
    for nid in order:
        nodes[nid]["constraints"].sort(key=lambda c: (c["distance"], c["from"]))
        nodes[nid]["conflict_count"] = sum(
            1 for c in conflicts if c["severity"] == "error" and c["node"] == nid
        )

    conflicts.sort(key=lambda c: (0 if c["severity"] == "error" else 1, c["distance"], c["node"], c["ancestor"]))

    for index, conflict in enumerate(conflicts, start=1):
        conflict["id"] = "C%03d" % index

    warnings = list(parse_warnings)
    for item in unresolved:
        warnings.append(
            "未解析依赖：%s -> %s（%s）" % (item["source"], item["reference"], item["reason"])
        )

    error_count = sum(1 for c in conflicts if c["severity"] == "error")
    warning_count = sum(1 for c in conflicts if c["severity"] == "warning")
    node_list = [nodes[nid] for nid in order]

    status = "clean"
    if error_count:
        status = "conflict"
    elif warning_count or warnings:
        status = "warning"

    result = {
        "manifest_name": display_name,
        "status": status,
        "summary": {
            "packages": len(order),
            "edges": len(edges),
            "conflicts": error_count,
            "license_warnings": warning_count,
            "unresolved": len(unresolved),
            "warnings": len(warnings),
        },
        "nodes": node_list,
        "edges": edges,
        "conflicts": conflicts,
        "unresolved": unresolved,
        "warnings": warnings,
    }
    return result


def _reconstruct_path(parents: Dict[str, Optional[str]], start: str, end: str) -> List[str]:
    path = [end]
    cur: Optional[str] = end
    while cur != start:
        cur = parents.get(cur)
        if cur is None:
            break
        path.append(cur)
    path.reverse()
    return path


def _distance_to(parents: Dict[str, Optional[str]], start: str, end: str) -> int:
    return len(_reconstruct_path(parents, start, end)) - 1


def _empty_result(name: str) -> Dict[str, Any]:
    return {
        "manifest_name": name,
        "status": "clean",
        "summary": {
            "packages": 0,
            "edges": 0,
            "conflicts": 0,
            "license_warnings": 0,
            "unresolved": 0,
            "warnings": 0,
        },
        "nodes": [],
        "edges": [],
        "conflicts": [],
        "unresolved": [],
        "warnings": [],
    }


def filter_result(result: Dict[str, Any], package: Optional[str]) -> Dict[str, Any]:
    """按包名/id（大小写不敏感子串）过滤冲突与节点。

    匹配范围：冲突路径上的任意节点，保证“最短路径涉及该包”的冲突也被保留。
    """
    if not package:
        filtered = dict(result)
        filtered["filtered"] = False
        filtered["filter"] = None
        return filtered
    needle = package.strip().lower()

    def hit(node_id_str: str) -> bool:
        return needle in node_id_str.lower()

    nodes = [n for n in result.get("nodes", []) if hit(n["id"]) or hit(n["name"])]
    conflicts = [
        c
        for c in result.get("conflicts", [])
        if any(hit(p) for p in c["path"])
    ]
    edges = [
        e
        for e in result.get("edges", [])
        if hit(e["source"]) or hit(e["target"])
    ]
    unresolved = [
        u
        for u in result.get("unresolved", [])
        if hit(u["source"]) or hit(u["reference"])
    ]
    filtered = dict(result)
    filtered.update(
        {
            "nodes": nodes,
            "edges": edges,
            "conflicts": conflicts,
            "unresolved": unresolved,
            "filtered": True,
            "filter": package,
        }
    )
    filtered["summary"] = dict(result["summary"])
    filtered["summary"].update(
        {
            "packages": len(nodes),
            "edges": len(edges),
            "conflicts": sum(1 for c in conflicts if c["severity"] == "error"),
            "license_warnings": sum(1 for c in conflicts if c["severity"] == "warning"),
            "unresolved": len(unresolved),
            "filtered_packages": len(nodes),
        }
    )
    return filtered
