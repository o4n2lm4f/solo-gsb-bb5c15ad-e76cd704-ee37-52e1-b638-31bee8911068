"""许可证规范化与许可证兼容矩阵。

兼容方向按 *父项目（派生/分发作品）许可证 -> 依赖许可证* 判定，
即父许可证能否容纳依赖许可证（是否可将依赖代码整合进父作品一起分发）。

覆盖的许可证：
    宽松型 : MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, Unlicense, CC0-1.0
    弱 copyleft : MPL-2.0, LGPL-2.1, LGPL-3.0
    强 copyleft : GPL-2.0, GPL-3.0, AGPL-3.0
    专有 : Proprietary

未识别的许可证一律保留原文并标记 unknown，按“需人工确认”告警处理。

多许可证候选：许可证文本若为矩阵内标识以 `` OR `` 连接的表达式
（如 ``MIT OR GPL-2.0``），或声明了多个并列许可证条目，则解析为候选集合：
存在任一可兼容组合即不判硬冲突，全部组合冲突才判硬冲突，其余为需人工确认。
含 ``AND``、括号或未知标识的表达式不做候选拆分，仍按未知处理。
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

# --- 许可证元数据 -----------------------------------------------------------

PERMISSIVE = "permissive"
WEAK_COPYLEFT = "weak-copyleft"
STRONG_COPYLEFT = "strong-copyleft"
PROPRIETARY = "proprietary"
UNKNOWN = "unknown"
MULTI = "multi"  # 多个候选许可证（OR 选择关系），非矩阵中的单一许可证

CATEGORIES: Dict[str, str] = {
    "MIT": PERMISSIVE,
    "ISC": PERMISSIVE,
    "BSD-2-Clause": PERMISSIVE,
    "BSD-3-Clause": PERMISSIVE,
    "Apache-2.0": PERMISSIVE,
    "Unlicense": PERMISSIVE,
    "CC0-1.0": PERMISSIVE,
    "MPL-2.0": WEAK_COPYLEFT,
    "LGPL-2.1": WEAK_COPYLEFT,
    "LGPL-3.0": WEAK_COPYLEFT,
    "GPL-2.0": STRONG_COPYLEFT,
    "GPL-3.0": STRONG_COPYLEFT,
    "AGPL-3.0": STRONG_COPYLEFT,
    "Proprietary": PROPRIETARY,
}

CATEGORY_LABELS: Dict[str, str] = {
    PERMISSIVE: "宽松型",
    WEAK_COPYLEFT: "弱 Copyleft",
    STRONG_COPYLEFT: "强 Copyleft",
    PROPRIETARY: "专有",
    UNKNOWN: "未知",
    MULTI: "多候选",
}

CATEGORY_NOTES: Dict[str, str] = {
    PERMISSIVE: "宽松许可证，基本不向集成方施加分发约束。",
    WEAK_COPYLEFT: "弱 copyleft：库本身修改需开源，动态链接通常可被专有作品使用。",
    STRONG_COPYLEFT: "强 copyleft：整体派生作品须以同一许可证开源，排斥专有代码。",
    PROPRIETARY: "专有许可证，不允许自由再分发/修改，能否使用需逐项确认。",
    UNKNOWN: "未在矩阵中识别，无法自动判定兼容性，需要人工确认。",
    MULTI: "声明了多个候选许可证（OR 选择关系），可任选其一，按候选组合判定兼容性。",
}

# 规范标识的小写形式 -> 规范标识（gpl-2.0 -> GPL-2.0 等）
_CANONICAL_LOWER = {token.lower(): token for token in CATEGORIES}

# 常见别名 -> 规范 SPDX 标识
_ALIASES: Dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "isc": "ISC",
    "isc license": "ISC",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd2": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd3": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "apache": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "mpl": "MPL-2.0",
    "mpl2": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl": "LGPL-3.0",
    "lgpl2": "LGPL-2.1",
    "lgpl-2": "LGPL-2.1",
    "lgpl 2.1": "LGPL-2.1",
    "lgpl-2.1-only": "LGPL-2.1",
    "lgpl3": "LGPL-3.0",
    "lgplv2": "LGPL-2.1",
    "lgplv3": "LGPL-3.0",
    "lgpl-3": "LGPL-3.0",
    "lgpl 3.0": "LGPL-3.0",
    "lgpl-3.0-only": "LGPL-3.0",
    "gpl": "GPL-3.0",
    "gpl2": "GPL-2.0",
    "gpl-2": "GPL-2.0",
    "gpl 2": "GPL-2.0",
    "gpl 2.0": "GPL-2.0",
    "gplv2": "GPL-2.0",
    "gpl-2.0-only": "GPL-2.0",
    "gpl3": "GPL-3.0",
    "gpl-3": "GPL-3.0",
    "gpl 3": "GPL-3.0",
    "gpl 3.0": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gpl-3.0-only": "GPL-3.0",
    "agpl": "AGPL-3.0",
    "agpl3": "AGPL-3.0",
    "agpl-3": "AGPL-3.0",
    "agpl 3": "AGPL-3.0",
    "agpl 3.0": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "agpl-3.0-only": "AGPL-3.0",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "cc0 1.0 universal": "CC0-1.0",
    "public domain": "CC0-1.0",
    "proprietary": "Proprietary",
    "commercial": "Proprietary",
    "all rights reserved": "Proprietary",
    "closed": "Proprietary",
    "closed source": "Proprietary",
}


def normalize_license(raw: object) -> Tuple[str, str, bool]:
    """把许可证文本规范化为 SPDX 标识。

    返回 ``(display, token, known)``：

    * display — 始终保留用户原文（去除首尾空白后），未知时原样展示；
    * token   — 规范标识，未知时为原文小写压缩形式；
    * known   — 是否被矩阵识别。
    """
    text = "" if raw is None else str(raw).strip()
    display = text if text else "UNLICENSED"
    key = " ".join(text.lower().split())
    # 规范标识本身的小写连字符形式（gpl-2.0 / apache-2.0 / bsd-2-clause …）
    if key in _CANONICAL_LOWER:
        return display, _CANONICAL_LOWER[key], True
    canonical = _ALIASES.get(key)
    if canonical:
        return display, canonical, True
    # 形如 "GPL-2.0-or-later" 这类带后缀的 SPDX 写法按该版本处理
    stripped = key.removesuffix("-or-later").removesuffix("-only")
    canonical = (
        _ALIASES.get(stripped)
        or _CANONICAL_LOWER.get(stripped)
        or (stripped if stripped in CATEGORIES else None)
    )
    if canonical:
        return display, canonical, True
    if not text:
        return display, "unlicensed", False
    return display, key.replace(" ", "_"), False


# --- 多许可证候选解析 --------------------------------------------------------

# 候选连接词：接受两侧带空白的 OR（大小写不敏感，如 "MIT OR Apache-2.0" / "MIT or ISC"）
_OR_RE = re.compile(r"\s+OR\s+", re.IGNORECASE)
# 含 AND / WITH / 括号等结构的表达式一律不做候选拆分，按未知处理
_COMPLEX_RE = re.compile(r"\(|\)|\s+AND\s+|\s+WITH\s+|;|,", re.IGNORECASE)


def _split_or_expression(text: str) -> Optional[List[str]]:
    """把纯 OR 表达式拆成原子字符串。

    仅当表达式不含括号、AND、WITH 等结构时拆分（OR 大小写不敏感）；
    否则返回 ``None``，调用方按未知表达式处理。
    """
    stripped = text.strip()
    if not stripped:
        return None
    if _COMPLEX_RE.search(stripped):
        return None
    if not _OR_RE.search(stripped):
        return None
    parts = [part.strip() for part in _OR_RE.split(stripped)]
    return parts if all(parts) else None


def parse_license_entries(raw: object) -> Dict[str, Any]:
    """解析许可证字段（原生 manifest 与 CycloneDX 共用），识别多许可证候选。

    接受：

    * ``None`` / 空 —— 未知（UNLICENSED）；
    * 字符串 —— 单个许可证，或矩阵内标识以 `` OR `` 连接的纯选择表达式；
    * 数组 —— 多个并列许可证条目，元素可以是字符串或形如
      ``{"id": ...}`` / ``{"name": ...}`` / ``{"license": {...}}`` /
      ``{"expression": ...}`` 的 CycloneDX 条目（原生 manifest 同样接受）。

    多个并列条目按候选处理（条目顺序去重后并入候选集合）。含 AND、括号或
    未知标识的表达式不做拆分，整体按未知处理。

    返回富信息字典（在 ``license_info`` 基础上增加）：

    * ``candidates`` —— 候选许可证列表，每项为一次 ``license_info`` 的结果，
      全部为矩阵内已知许可证时才有多项；
    * ``multi`` —— 是否为多候选（``candidates`` 去重后多于一个）。
    """
    # 1) 归一为“原子条目字符串”列表（保留展示用原文）
    atoms: List[str] = []
    if isinstance(raw, list):
        for entry in raw:
            atom = _entry_to_text(entry)
            if atom:
                atoms.append(atom)
    elif raw is not None and str(raw).strip():
        atoms.append(str(raw).strip())

    if not atoms:
        info = license_info(None)
        info["candidates"] = [info]
        info["multi"] = False
        return info

    # 2) 每个原子条目要么是单个已知许可证，要么是纯 OR 表达式；
    #    任何原子无法全部解析为矩阵内标识时，整个字段按未知处理（不丢弃原文）。
    tokens: List[str] = []
    for atom in atoms:
        parts = _split_or_expression(atom)
        if parts is None:
            parts = [atom]
        for part in parts:
            _display, token, known = normalize_license(part)
            if not known:
                return _unknown_multi_info(raw)
            tokens.append(token)

    # 3) 按规范标识去重（保持声明顺序）
    unique_tokens: List[str] = []
    for token in tokens:
        if token not in unique_tokens:
            unique_tokens.append(token)

    candidates = [license_info(token) for token in unique_tokens]
    if len(unique_tokens) == 1:
        info = dict(candidates[0])
        info["candidates"] = candidates
        info["multi"] = False
        return info

    # 多候选：展示文本保留原始表达式（并列条目用 OR 连接），token 用规范 OR 表达式
    display = _build_display(atoms)
    info = {
        "raw": "" if raw is None else _raw_text(raw),
        "display": display,
        "token": " OR ".join(unique_tokens),
        "known": True,
        "category": MULTI,
        "category_label": CATEGORY_LABELS[MULTI],
        "note": CATEGORY_NOTES[MULTI],
        "candidates": candidates,
        "multi": True,
    }
    return info


def _entry_to_text(entry: object) -> str:
    """把一个许可证条目（字符串或 dict）提取为许可证文本。

    支持 CycloneDX 1.4/1.5 的 ``{"license": {"id"|"name": ...}}`` 与
    ``{"expression": ...}``，也兼容直接给 ``{"id"|"name": ...}`` 的简写；
    ``type``（conjunctive/disjunctive 元数据）不作为许可证名。
    """
    if isinstance(entry, str):
        return entry.strip()
    if isinstance(entry, dict):
        license_obj = entry.get("license")
        if isinstance(license_obj, dict):
            spdx_id = str(license_obj.get("id") or "").strip()
            if spdx_id:
                return spdx_id
            license_name = str(license_obj.get("name") or "").strip()
            if license_name:
                return license_name
        for key in ("expression", "id", "name"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _build_display(atoms: List[str]) -> str:
    """构造多候选的展示文本：优先保留原始 OR 表达式，并列条目用 OR 连接。"""
    if len(atoms) == 1:
        return atoms[0]
    return " OR ".join(atoms)


def _raw_text(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    return str(raw)


def _unknown_multi_info(raw: object) -> Dict[str, Any]:
    """无法解析为候选集合时，整体回退为未知（保持单许可证语义）。"""
    if isinstance(raw, list):
        atoms = [_entry_to_text(e) for e in raw]
        text = " OR ".join(atom for atom in atoms if atom)
    else:
        text = "" if raw is None else str(raw)
    info = license_info(text)
    info["candidates"] = [dict(info)]
    info["multi"] = False
    return info


# --- 兼容性判定 -------------------------------------------------------------

OK = "ok"
CONFLICT = "conflict"
WARNING = "warning"


def imposes_constraint(token: str) -> bool:
    """该许可证是否会向集成它的父作品施加传递约束。"""
    return CATEGORIES.get(token) in (
        WEAK_COPYLEFT,
        STRONG_COPYLEFT,
        PROPRIETARY,
        UNKNOWN,
    )


def compatibility(parent_token: str, dep_token: str) -> Tuple[str, str]:
    """判定 *父许可证 parent* 能否容纳 *依赖许可证 dep*。

    返回 ``(状态, 中文原因)``，状态为 ok / conflict / warning。
    """
    parent_cat = CATEGORIES.get(parent_token, UNKNOWN)
    dep_cat = CATEGORIES.get(dep_token, UNKNOWN)

    if parent_cat == UNKNOWN or dep_cat == UNKNOWN:
        return (
            WARNING,
            "涉及未在兼容矩阵中识别的许可证，无法自动判定，需要人工确认。",
        )

    if parent_token == dep_token:
        return OK, "同一许可证，天然兼容。"

    if parent_cat == PERMISSIVE:
        # 宽松许可证可容纳几乎一切，但专有依赖仍需单独确认授权
        if dep_cat == PROPRIETARY:
            return WARNING, "父许可证为宽松型，但依赖为专有许可证，使用与再分发需单独确认授权。"
        return OK, "宽松许可证对集成依赖无 copyleft 约束。"

    if parent_token == "MPL-2.0":
        if dep_cat == PERMISSIVE:
            return OK, "MPL-2.0 允许文件级混用宽松许可证代码。"
        if dep_token == "LGPL-2.1":
            return CONFLICT, "MPL-2.0 与 LGPL-2.1 的条款相互不兼容，无法将两者组合进同一作品。"
        if dep_token in ("GPL-2.0", "AGPL-3.0"):
            return CONFLICT, "MPL-2.0 文件与 %s 组合时升级条款不被接受，属于不兼容组合。" % dep_token
        if dep_token in ("LGPL-3.0", "GPL-3.0"):
            return OK, "MPL-2.0 提供“按 GPL/LGPL 二级许可”选项，可与 %s 组合。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "MPL-2.0 要求被覆盖文件保持 MPL 并提供源码，不能并入专有闭源作品。"

    if parent_token == "LGPL-2.1":
        if dep_cat == PERMISSIVE:
            return OK, "LGPL-2.1 作品可以集成宽松许可证代码。"
        if dep_token in ("MPL-2.0", "LGPL-3.0", "GPL-3.0", "AGPL-3.0"):
            return CONFLICT, "LGPL-2.1 作品不能由 %s 代码派生（许可证升级方向不被允许）。" % dep_token
        if dep_token == "GPL-2.0":
            return OK, "LGPL-2.1 允许按 GPL-2.0 二级许可重新发布。"
        if dep_cat == PROPRIETARY:
            return CONFLICT, "LGPL-2.1 不允许将受其覆盖的库代码并入专有作品（仅独立链接例外）。"

    if parent_token == "LGPL-3.0":
        if dep_cat == PERMISSIVE:
            return OK, "LGPL-3.0 作品可以集成宽松许可证代码。"
        if dep_token == "MPL-2.0":
            return OK, "MPL-2.0 可按 GPL 兼容二级许可并入 LGPL-3.0 作品。"
        if dep_token == "LGPL-2.1":
            return OK, "LGPL-3.0 允许纳入早期版本 LGPL-2.1 的代码。"
        if dep_token in ("GPL-3.0", "AGPL-3.0"):
            return OK, "LGPL-3.0 允许按 GPL-3.0/AGPL-3.0 二级许可重新发布。"
        if dep_token == "GPL-2.0":
            return CONFLICT, "GPL-2.0（仅 v2）不能升级到 LGPL-3.0，无法并入 LGPL-3.0 作品。"
        if dep_cat == PROPRIETARY:
            return CONFLICT, "LGPL-3.0 不允许将受其覆盖的库代码并入专有作品（仅独立链接例外）。"

    if parent_token == "GPL-2.0":
        if dep_cat == PERMISSIVE and parent_token != dep_token:
            if dep_token == "Apache-2.0":
                return CONFLICT, "GPL-2.0 与 Apache-2.0 专利条款冲突，不能组合进同一作品。"
            return OK, "宽松许可证代码可被 GPL-2.0 作品吸纳。"
        if dep_token in ("LGPL-2.1",):
            return OK, "LGPL-2.1 可重新许可为 GPL-2.0，可被 GPL-2.0 作品吸纳。"
        if dep_token in (
            "MPL-2.0",
            "LGPL-3.0",
            "GPL-3.0",
            "AGPL-3.0",
        ):
            return CONFLICT, "%s 的要求无法在 GPL-2.0（仅 v2）条款下满足，方向不兼容。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "GPL-2.0 整体作品必须开源，不能与专有代码组合分发。"

    if parent_token == "GPL-3.0":
        if dep_cat == PERMISSIVE:
            return OK, "GPL-3.0 明确兼容宽松许可证（含 Apache-2.0）。"
        if dep_token == "MPL-2.0":
            return OK, "MPL-2.0 提供 GPL 二级许可，可与 GPL-3.0 组合。"
        if dep_token in ("LGPL-2.1", "LGPL-3.0"):
            return OK, "%s 代码可升级到 GPL-3.0 后纳入 GPL-3.0 作品。" % dep_token
        if dep_token in ("GPL-2.0", "AGPL-3.0"):
            return CONFLICT, "%s 不能单向升级到 GPL-3.0（GPLv2-only 不兼容，AGPL 需另行满足网络条款）。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "GPL-3.0 整体作品必须开源，不能与专有代码组合分发。"

    if parent_token == "AGPL-3.0":
        if dep_cat == PERMISSIVE:
            return OK, "AGPL-3.0 兼容宽松许可证（含 Apache-2.0）。"
        if dep_token == "MPL-2.0":
            return OK, "MPL-2.0 提供 GPL 二级许可，可与 AGPL-3.0 组合。"
        if dep_token in ("LGPL-2.1", "LGPL-3.0"):
            return OK, "%s 代码可升级后纳入 AGPL-3.0 作品。" % dep_token
        if dep_token in ("GPL-2.0", "GPL-3.0"):
            return CONFLICT, "%s 与 AGPL-3.0 的条款不能相互满足，无法单向组合。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "AGPL-3.0 网络交互也触发开源义务，不能与专有代码组合。"

    if parent_cat == PROPRIETARY:
        if dep_cat == PERMISSIVE:
            return OK, "宽松许可证代码可被专有作品使用（保留声明即可）。"
        if dep_token in ("LGPL-2.1", "LGPL-3.0", "MPL-2.0"):
            return WARNING, (
                "%s 属于文件/库级弱 copyleft：满足独立链接、可替换及源码提供义务时可被专有作品使用，"
                "静态合并则不兼容，需要人工确认链接方式。" % dep_token
            )
        if dep_cat == STRONG_COPYLEFT:
            return CONFLICT, "%s 强 copyleft 会使整个专有作品被迫开源，不能集成。" % dep_token
        if dep_cat == PROPRIETARY:
            return WARNING, "双方均为专有许可证，能否一起分发取决于各自商业授权，需要人工确认。"

    # 理论上不会到达
    return WARNING, "无法自动判定，需要人工确认。"


# --- 多许可证候选的组合判定 --------------------------------------------------


def compatibility_candidates(
    parent_tokens: List[str],
    dep_tokens: List[str],
) -> Dict[str, Any]:
    """对祖先与依赖的候选许可证逐一调用兼容矩阵，按组合结果汇总判定。

    候选语义为 *任选其一*（SPDX OR）：祖先可在其候选中选择一个许可证，
    依赖同理；只要存在一个 ``(祖先候选, 依赖候选)`` 组合兼容，就不必报
    硬冲突。汇总规则：

    * 全部组合冲突 → ``conflict``（硬冲突）；
    * 全部组合兼容 → ``ok``（通过，不报条目）；
    * 其余（既有冲突/告警也有兼容，或含需人工确认）→ ``warning``（需人工确认）。

    返回 ``status``、汇总说明 ``reason`` 与每个组合的逐条判定 ``combinations``
    （含 parent / dep / status / reason）。单许可证时只有一个组合，结果与
    直接调用 :func:`compatibility` 完全一致（含原始中文原因）。
    """
    parent_tokens = list(dict.fromkeys(parent_tokens))
    dep_tokens = list(dict.fromkeys(dep_tokens))
    combinations: List[Dict[str, str]] = []
    for parent_token in parent_tokens:
        for dep_token in dep_tokens:
            status, reason = compatibility(parent_token, dep_token)
            combinations.append(
                {
                    "parent": parent_token,
                    "dep": dep_token,
                    "status": status,
                    "reason": reason,
                }
            )

    statuses = {item["status"] for item in combinations}
    if len(combinations) == 1:
        # 单许可证：严格保持原有语义（原因也沿用矩阵原文）
        status = combinations[0]["status"]
        reason = combinations[0]["reason"]
    elif statuses == {CONFLICT}:
        status = CONFLICT
        reason = (
            "祖先与依赖各声明了多个候选许可证（OR 选择关系），"
            "共 %d 个候选组合，全部与兼容矩阵冲突，判为硬冲突。" % len(combinations)
        )
    elif statuses == {OK}:
        status = OK
        reason = (
            "祖先与依赖各声明了多个候选许可证（OR 选择关系），"
            "%d 个候选组合全部兼容。" % len(combinations)
        )
    else:
        status = WARNING
        ok_count = sum(1 for item in combinations if item["status"] == OK)
        conflict_count = sum(1 for item in combinations if item["status"] == CONFLICT)
        warning_count = len(combinations) - ok_count - conflict_count
        reason = (
            "祖先与依赖各声明了多个候选许可证（OR 选择关系），共 %d 个候选组合："
            "%d 个兼容、%d 个冲突、%d 个需人工确认；可选择兼容组合则不构成硬冲突，"
            "但并非全部组合兼容，需人工确认最终采用的许可证。"
            % (len(combinations), ok_count, conflict_count, warning_count)
        )

    return {
        "status": status,
        "reason": reason,
        "combinations": combinations,
        "parent_candidates": parent_tokens,
        "dep_candidates": dep_tokens,
    }


@lru_cache(maxsize=1)
def build_matrix() -> List[Dict[str, object]]:
    """生成完整兼容矩阵（仅包含已知许可证），供 API 与前端展示。"""
    # MULTI 只是候选集合的占位分类，不参与矩阵；矩阵只列具体许可证
    tokens = [token for token in CATEGORIES if CATEGORIES[token] != MULTI]
    rows: List[Dict[str, object]] = []
    for parent in tokens:
        cells: List[Dict[str, str]] = []
        for dep in tokens:
            status, reason = compatibility(parent, dep)
            cells.append({"dep": dep, "status": status, "reason": reason})
        rows.append(
            {
                "parent": parent,
                "category": CATEGORIES[parent],
                "cells": cells,
            }
        )
    return rows


def license_info(raw: object) -> Dict[str, object]:
    """规范化许可证并返回富信息字典。"""
    display, token, known = normalize_license(raw)
    category = CATEGORIES.get(token, UNKNOWN)
    info: Dict[str, object] = {
        "raw": "" if raw is None else str(raw),
        "display": display,
        "token": token,
        "known": known,
        "category": category,
        "category_label": CATEGORY_LABELS[category],
        "note": CATEGORY_NOTES[category],
    }
    # 单许可证：候选集合就是自身（多候选解析由 parse_license_entries 负责）
    info["candidates"] = [dict(info)]
    info["multi"] = False
    return info
