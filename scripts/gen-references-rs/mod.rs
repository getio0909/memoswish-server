//! 从实际目录、权限和合成默认配置生成测试参考。

mod ast;
mod configuration;
mod mcp;
mod routes;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn header(title: &str) -> String {
    format!("# {title}\n\n由服务端代码离线生成。\n\n")
}

fn cell(value: impl AsRef<str>) -> String {
    value.as_ref().replace('|', "&#124;").replace(['\n', '\r'], " ")
}

fn render() -> BTreeMap<String, String> {
    let sources = ast::Sources::load(&root());
    BTreeMap::from([
        ("mcp-tools.md".into(), mcp::render(&sources)),
        ("configuration.md".into(), configuration::render(&sources)),
        ("http-endpoints.md".into(), routes::render(&sources)),
    ])
}

fn check_documents(directory: &Path, expected: &BTreeMap<String, String>) -> Result<(), String> {
    for (name, text) in expected {
        let actual = std::fs::read_to_string(directory.join(name)).map_err(|e| format!("{name}: {e}"))?;
        if actual != *text {
            return Err(format!("{name} has drifted"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../compatibility-inventory.rs"]
mod compatibility_inventory;
