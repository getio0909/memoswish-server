// 从冻结清单中解析该检查点的真实目录，同时拒绝缺失或混用的布局。
pub fn directory(root: &std::path::Path, row: &serde_json::Value, backend: &str) -> std::path::PathBuf {
    let id = row["id"].as_str().unwrap();
    let suffix = format!("/migrations/{backend}");
    let mut directories = std::collections::BTreeSet::new();
    for file in row["files"].as_array().unwrap() {
        let source = std::path::Path::new(file["source"].as_str().unwrap());
        let Some(parent) = source.parent() else { continue };
        if !parent.to_string_lossy().ends_with(&suffix) || source.extension().is_none_or(|ext| ext != "sql") {
            continue;
        }
        assert!(
            ["learntok", "memoswish"]
                .iter()
                .any(|name| { parent == std::path::Path::new(&format!("server/crates/{name}-storage{suffix}")) })
        );
        let snapshot = std::path::Path::new("compatibility/history").join(id).join(source);
        assert_eq!(file["path"].as_str().unwrap(), snapshot.to_str().unwrap().replace('\\', "/"));
        directories.insert(root.join(snapshot.parent().unwrap()));
    }
    assert_eq!(directories.len(), 1, "Expected one frozen migration directory");
    directories.pop_first().unwrap()
}
