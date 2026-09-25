"""CycloneDX JSON（SBOM）导入：把 BOM 组件与依赖图转换为审计节点与依赖边。

识别规则（满足其一即按 CycloneDX 处理，见 ``is_cyclonedx``）：

* 顶层存在 ``bomFormat`` 字段（取值必须为 ``CycloneDX``，否则报错）；
* 或顶层存在数组形式的 ``components`` 且未使用旧格式的 ``packages``。

导入约定：

* 每个 ``components[]`` 组件规范化为一个包节点（``name@version``），组件的
  ``bom-ref`` 记录到节点的 ``bom_refs`` 字段，并建立 ``bom-ref -> 节点`` 映射；
* 组件许可证取 ``licenses`` 中的 SPDX ``id``、``expression`` 或兜底 ``license.name``；
  纯 `` OR `` 表达式与多个并列许可证条目解析为**多许可证候选**，含 AND、括号或
  未知标识的表达式仍按未知处理，缺失许可证按未知（UNLICENSED）处理；
* ``dependencies[]`` 按 ``ref`` / ``dependsOn`` 还原依赖边（方向：使用方 -> 被依赖方），
  引用不到任何组件 bom-ref 的条目保留为未解析告警，不凭空造节点；
* 为避免静默合并，以下情况直接判定为解析错误（API 层返回 422）：
  同一 ``bom-ref`` 重复出现；同名同版本的组件许可证不一致。

解析成功后完全复用 ``analyzer._build_result`` 的传递约束与最短路径冲突分析，
审计结果与旧格式 manifest 一样进入历史列表并可按原方式导出。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from . import analyzer, licenses as lic

EDGE_SOURCE = "cyclonedx-dependencies"


def is_cyclonedx(manifest: Any) -> bool:
    """判断 manifest 是否应按 CycloneDX BOM 解析。"""
    if not isinstance(manifest, dict):
        return False
    if manifest.get("bomFormat") is not None:
        return True
    # 旧格式用 packages 声明节点；没有 packages 却带 components 数组时按 CycloneDX 处理
    return "packages" not in manifest and isinstance(manifest.get("components"), list)


def analyze_bom(bom: Dict[str, Any], manifest_name: str = "uploaded-manifest") -> Dict[str, Any]:
    """解析 CycloneDX BOM 并复用 analyzer 的传递约束/冲突分析。

    返回与 ``analyzer.analyze_manifest`` 相同结构的结果字典；
    解析失败时返回 ``status == "error"`` 的结果（API 层据此返回 422）。
    """
    display_name = _display_name(bom, manifest_name)

    bom_format = bom.get("bomFormat")
    if bom_format is not None and str(bom_format).strip().lower() != "cyclonedx":
        return _error_result(
            display_name,
            "bomFormat 为 %r，仅支持 CycloneDX BOM。" % (bom_format,),
        )

    raw_components = bom.get("components")
    if raw_components is None:
        raw_components = []
    if not isinstance(raw_components, list):
        return _error_result(display_name, "CycloneDX components 字段必须是数组。")

    raw_dependencies = bom.get("dependencies")
    if raw_dependencies is None:
        raw_dependencies = []
    if not isinstance(raw_dependencies, list):
        return _error_result(
            display_name,
            "CycloneDX dependencies 字段必须是数组（形如 [{\"ref\": ..., \"dependsOn\": [...]}]）。",
        )

    warnings: List[str] = []
    warning_seen: Set[str] = set()
    warn = lambda msg: analyzer._add_warning(warnings, warning_seen, msg)

    # 1) 注册组件节点并建立 bom-ref -> 节点 映射
    nodes: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    ref_map: Dict[str, str] = {}
    seen_refs: Set[str] = set()

    for component in raw_components:
        if not isinstance(component, dict):
            warn("components 中存在非对象条目，已跳过：%r" % (component,))
            continue
        name = str(component.get("name") or "").strip()
        if not name:
            warn("components 中存在缺少 name 的条目，已跳过：%r" % (component,))
            continue
        version, _ = analyzer.clean_version(component.get("version"))
        nid = analyzer.node_id(name, version)
        info = lic.parse_license_entries(_extract_license(component, warn))

        bom_ref = component.get("bom-ref")
        bom_ref = str(bom_ref).strip() if bom_ref is not None else ""
        if bom_ref:
            if bom_ref in seen_refs:
                return _error_result(
                    display_name,
                    "components 中 bom-ref 重复：%r。为避免静默合并组件，"
                    "已中止导入，请去重后重新提交。" % bom_ref,
                )
            seen_refs.add(bom_ref)

        existing = nodes.get(nid)
        if existing is not None:
            new_tokens = sorted(
                str(item.get("token"))
                for item in info.get("candidates", [])
                if item.get("known")
            ) or [str(info.get("token"))]
            old_tokens = sorted(analyzer.license_tokens(existing))
            if old_tokens != new_tokens or bool(existing["license_known"]) != bool(info["known"]):
                return _error_result(
                    display_name,
                    "组件 %s 被多次声明且许可证不一致（%s vs %s）。为避免静默合并，"
                    "已中止导入，请统一许可证后重新提交。"
                    % (nid, existing["license_display"], info["display"]),
                )
            # 同名同版本且许可证一致：合并为同一节点，补充 bom-ref 映射
            if bom_ref:
                existing["bom_refs"].append(bom_ref)
                ref_map[bom_ref] = nid
            continue

        nodes[nid] = analyzer._node_from_info(
            nid, name, version, info, {"bom_refs": [bom_ref] if bom_ref else []}
        )
        order.append(nid)
        if bom_ref:
            ref_map[bom_ref] = nid

    # 2) 按 ref / dependsOn 还原依赖边
    edges: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, str]] = []
    unresolved_seen: Set[Tuple[str, str]] = set()

    def mark_unresolved(source: str, ref: str, reason: str) -> None:
        analyzer._mark_unresolved(unresolved, unresolved_seen, source, ref, reason)

    for entry in raw_dependencies:
        if not isinstance(entry, dict):
            warn("dependencies 中存在非对象条目，已跳过：%r" % (entry,))
            continue
        ref = str(entry.get("ref") or "").strip()
        if not ref:
            warn("dependencies 中存在缺少 ref 的条目，已跳过：%r" % (entry,))
            continue
        source = ref_map.get(ref)
        if source is None:
            mark_unresolved("?", ref, "dependencies 条目的 ref 未匹配任何组件 bom-ref")
            continue
        depends_on = entry.get("dependsOn")
        if depends_on is None:
            continue
        if not isinstance(depends_on, list):
            warn("dependencies 中 %r 的 dependsOn 不是数组，已忽略。" % ref)
            continue
        for target_ref in depends_on:
            target_text = str(target_ref).strip()
            if not target_text:
                continue
            target = ref_map.get(target_text)
            if target is None:
                mark_unresolved(
                    source, target_text, "dependsOn 引用的 bom-ref 未在 components 中声明"
                )
                continue
            if source != target:
                edges.append({"source": source, "target": target, "from": EDGE_SOURCE})

    # 去重边（保留首次出现）
    deduped_edges: List[Dict[str, Any]] = []
    seen_edges: Set[Tuple[str, str]] = set()
    for edge in edges:
        key = (edge["source"], edge["target"])
        if key not in seen_edges:
            seen_edges.add(key)
            deduped_edges.append(edge)

    result = analyzer._build_result(
        display_name, bom, nodes, order, deduped_edges, unresolved, warnings
    )
    result["source_format"] = "cyclonedx"
    return result


def _display_name(bom: Dict[str, Any], manifest_name: str) -> str:
    """BOM 显示名：顶层 name -> metadata.component.name -> 调用方给的默认名。"""
    name = str(bom.get("name") or "").strip()
    if not name:
        metadata = bom.get("metadata")
        if isinstance(metadata, dict):
            component = metadata.get("component")
            if isinstance(component, dict):
                name = str(component.get("name") or "").strip()
    return name or str(manifest_name).strip() or "cyclonedx-bom"


def _extract_license(component: Dict[str, Any], warn) -> Optional[List[Dict[str, Any]]]:
    """提取组件的 ``licenses`` 数组（保留并列条目结构）。

    返回值直接交给 :func:`licenses.parse_license_entries`：

    * 每个条目归一为 ``{"id"/"name"/"expression": 文本}``（字符串条目也兼容），
      SPDX ``id`` / ``expression`` / ``license.name`` 的取值优先级在解析器内统一处理；
    * 纯 `` OR `` 表达式与多个并列条目会被识别为多许可证候选；
      含 AND、括号或未知标识的表达式整体按未知处理；
    * 字段缺失或结构无法识别时返回 ``None``（按 UNLICENSED 未知处理）。
    """
    raw = component.get("licenses")
    if raw is None:
        return None
    if not isinstance(raw, list):
        warn(
            "组件 %r 的 licenses 字段不是数组，按缺失许可证处理。"
            % (component.get("name") or component.get("bom-ref") or "?")
        )
        return None
    entries: List[Dict[str, Any]] = []
    for entry in raw:
        if isinstance(entry, str):
            entries.append({"expression": entry})
        elif isinstance(entry, dict):
            entries.append(entry)
    return entries or None


def _error_result(display_name: str, message: str) -> Dict[str, Any]:
    return analyzer._empty_result(display_name) | {
        "status": "error",
        "error": message,
        "warnings": [],
    }
