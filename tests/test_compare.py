"""两次审计对比逻辑的自测：python -m tests.test_compare"""

from __future__ import annotations

from app import analyzer, compare as compare_mod


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _path_change_manifests(use_direct_edge: bool):
    # a(GPL-3.0) -> c(Proprietary) 是硬冲突；b(MIT) -> c 为需人工确认告警。
    # 基准审计额外有一条 a -> c 直边（最短路径 1 跳），目标审计删除该直边后
    # 最短路径变为 a -> b -> c（2 跳）。
    packages = [
        {"name": "a", "version": "1", "license": "GPL-3.0",
         "dependencies": ["b@1"]},
        {"name": "b", "version": "1", "license": "MIT",
         "dependencies": ["c@1"]},
        {"name": "c", "version": "1", "license": "Proprietary"},
    ]
    manifest = {"name": "path-demo", "packages": packages}
    if use_direct_edge:
        manifest["edges"] = [{"source": "a@1", "target": "c@1"}]
    return manifest


def test_node_pairing_and_path_change() -> None:
    base_manifest = _path_change_manifests(True)
    base_manifest["packages"].append({"name": "ghost-dep", "version": "1", "license": "MIT"})
    target_manifest = _path_change_manifests(False)
    target_manifest["packages"].append({"name": "new-d", "version": "1", "license": "MIT"})
    base = analyzer.analyze_manifest(base_manifest)
    target = analyzer.analyze_manifest(target_manifest)

    diff = compare_mod.compare_audits(base, target)
    _check("comparison is read only", diff["read_only"] is True)

    node_changes = {n["id"]: n["change"] for n in diff["nodes"]}
    _check("new-d added", node_changes.get("new-d@1") == compare_mod.ADDED, str(node_changes))
    _check("ghost-dep removed", node_changes.get("ghost-dep@1") == compare_mod.REMOVED)
    for nid in ("a@1", "b@1", "c@1"):
        _check("%s matched" % nid, node_changes.get(nid) == compare_mod.UNCHANGED)

    # (a,c) 双方都在；直边消失后最短路径改为 a -> b -> c
    _check("no added findings", diff["summary"]["findings"]["added"] == 0)
    _check("no removed findings", diff["summary"]["findings"]["removed"] == 0)
    _check("one changed finding", len(diff["changed"]) == 1, str(diff["changed"]))
    finding = diff["changed"][0]
    _check("changed key a->c", (finding["ancestor"], finding["node"]) == ("a@1", "c@1"))
    _check("path flagged changed", "path" in finding["fields_changed"])
    _check(
        "base shortest path direct",
        finding["base"]["path"] == ["a@1", "c@1"],
        str(finding["base"]["path"]),
    )
    _check(
        "target shortest path via b",
        finding["target"]["path"] == ["a@1", "b@1", "c@1"],
        str(finding["target"]["path"]),
    )
    # (b,c) 告警双方一致，不属于任何变化列表
    keys = {(f["ancestor"], f["node"]) for bucket in (diff["added"], diff["removed"], diff["changed"])
            for f in bucket}
    _check("unchanged warning omitted", ("b@1", "c@1") not in keys)

    summary = diff["summary"]
    _check("node added counted", summary["nodes"]["added"] == 1, str(summary["nodes"]))
    _check("node removed counted", summary["nodes"]["removed"] == 1)
    _check("node matched counted", summary["nodes"]["matched"] == 3)


def test_added_and_removed_finding() -> None:
    clean = analyzer.analyze_manifest(
        {"packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "MIT"},
        ]}
    )
    conflicting = analyzer.analyze_manifest(
        {"packages": [
            {"name": "app", "version": "1", "license": "GPL-3.0",
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "Proprietary"},
        ]}
    )

    forward = compare_mod.compare_audits(clean, conflicting)
    _check("one added finding", len(forward["added"]) == 1, str(forward["added"]))
    _check("added is error", forward["added"][0]["severity_target"] == "error")
    _check("added base side null", forward["added"][0]["base"] is None)
    _check("added carries target path",
           forward["added"][0]["target"]["path"] == ["app@1", "lib@1"])
    _check("added error counted", forward["summary"]["findings"]["added_errors"] == 1)

    backward = compare_mod.compare_audits(conflicting, clean)
    _check("one removed finding", len(backward["removed"]) == 1)
    _check("removed carries base path",
           backward["removed"][0]["base"]["path"] == ["app@1", "lib@1"])
    _check("removed target side null", backward["removed"][0]["target"] is None)


def test_severity_flip() -> None:
    warning_manifest = {
        "packages": [
            {"name": "root", "version": "1", "license": "MIT",
             "dependencies": ["x@1"]},
            {"name": "x", "version": "1", "license": "Proprietary"},
        ]
    }
    error_manifest = {
        "packages": [
            {"name": "root", "version": "1", "license": "GPL-3.0",
             "dependencies": ["x@1"]},
            {"name": "x", "version": "1", "license": "Proprietary"},
        ]
    }
    base = analyzer.analyze_manifest(warning_manifest)
    target = analyzer.analyze_manifest(error_manifest)
    diff = compare_mod.compare_audits(base, target)

    _check("exactly one changed finding", len(diff["changed"]) == 1, str(diff["changed"]))
    finding = diff["changed"][0]
    _check("severity flipped warning->error",
           finding["severity_base"] == "warning" and finding["severity_target"] == "error")
    _check("severity flagged", "severity" in finding["fields_changed"])
    _check("ancestor license flagged", "ancestor_license" in finding["fields_changed"])
    _check("path not flagged", "path" not in finding["fields_changed"])
    # 同一个包+版本（root@1）许可证发生变化，节点层面也应可见
    root = next(n for n in diff["nodes"] if n["id"] == "root@1")
    _check("matched node with license change",
           root["change"] == compare_mod.UNCHANGED and root["license_changed"] is True)


def test_meta_carried() -> None:
    base = analyzer.analyze_manifest({"name": "b", "packages": []})
    target = analyzer.analyze_manifest({"name": "t", "packages": []})
    base["audit_id"] = 7
    target["audit_id"] = 9
    diff = compare_mod.compare_audits(base, target)
    _check("base meta id", diff["base"]["audit_id"] == 7)
    _check("target meta id", diff["target"]["audit_id"] == 9)
    _check("base meta name", diff["base"]["manifest_name"] == "b")
    _check("direction hint present", "added" in diff["direction"])


def test_clean_manifests() -> None:
    base = analyzer.analyze_manifest(
        {"packages": [{"name": "a", "version": "1", "license": "MIT"}]}
    )
    target = analyzer.analyze_manifest(
        {"packages": [{"name": "a", "version": "1", "license": "ISC"}]}
    )
    diff = compare_mod.compare_audits(base, target)
    _check("no added/removed/changed findings",
           not diff["added"] and not diff["removed"] and not diff["changed"])
    _check("all counts zero", all(v == 0 for v in diff["summary"]["findings"].values()))
    # ISC 与 MIT 规范化 token 不同，但都不产生冲突；节点层仍可见许可证变化
    _check("node license change visible", diff["summary"]["nodes"]["license_changed"] == 1)
    _check("matched node count", diff["summary"]["nodes"]["matched"] == 1)


def main() -> None:
    test_node_pairing_and_path_change()
    test_added_and_removed_finding()
    test_severity_flip()
    test_meta_carried()
    test_clean_manifests()
    print("\nall compare tests passed.")


if __name__ == "__main__":
    main()
