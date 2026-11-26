use std::collections::{BTreeMap, BTreeSet};

use memoswish_mcp::{http::required_permissions, tools};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use syn::visit::{self, Visit};
use syn::{Expr, Lit, Token, parse::ParseStream, parse::Parser, punctuated::Punctuated};

use super::{ast, cell, header};

fn scopes(request: Value) -> String {
    let mut scopes: Vec<_> = required_permissions(&request).iter().map(|p| p.as_scope()).collect();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() { "无操作专属 scope".into() } else { scopes.join(" + ") }
}

#[derive(Default)]
struct MatchNames {
    target: String,
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for MatchNames {
    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        if ast::text(&expression.expr).replace(' ', "") == self.target {
            for arm in &expression.arms {
                let mut strings = ast::Strings::default();
                strings.visit_pat(&arm.pat);
                self.names.extend(strings.0);
            }
        }
        visit::visit_expr_match(self, expression);
    }
}

pub fn match_names(source: &syn::File, target: &str) -> BTreeSet<String> {
    let mut matches = MatchNames { target: target.into(), ..Default::default() };
    matches.visit_file(source);
    matches.names
}

// 静态描述只允许字面量与品牌 concat!/env!，其他动态表达式仍由原门禁拒绝。
fn brand_string(expression: Expr) -> syn::Result<String> {
    match expression {
        Expr::Lit(value) => match value.lit {
            Lit::Str(value) => Ok(value.value()),
            _ => Err(syn::Error::new_spanned(value, "expected string")),
        },
        Expr::Macro(value) if value.mac.path.is_ident("concat") => {
            let parts = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(value.mac.tokens)?;
            parts.into_iter().map(brand_string).collect::<syn::Result<Vec<_>>>().map(|parts| parts.concat())
        }
        Expr::Macro(value) if value.mac.path.is_ident("env") => {
            let key: syn::LitStr = syn::parse2(value.mac.tokens)?;
            match key.value().as_str() {
                "BRAND_EN_PRODUCT" => Ok(env!("BRAND_EN_PRODUCT").into()),
                "BRAND_ZH_PRODUCT" => Ok(env!("BRAND_ZH_PRODUCT").into()),
                _ => Err(syn::Error::new_spanned(key, "unsupported descriptor environment")),
            }
        }
        value => Err(syn::Error::new_spanned(value, "nonliteral descriptor")),
    }
}

fn static_json(input: ParseStream<'_>) -> syn::Result<Value> {
    if input.peek(syn::token::Brace) {
        let content;
        syn::braced!(content in input);
        let mut object = serde_json::Map::new();
        while !content.is_empty() {
            let key: syn::LitStr = content.parse()?;
            content.parse::<Token![:]>()?;
            object.insert(key.value(), static_json(&content)?);
            if content.is_empty() {
                break;
            }
            content.parse::<Token![,]>()?;
        }
        return Ok(Value::Object(object));
    }
    if input.peek(syn::token::Bracket) {
        let content;
        syn::bracketed!(content in input);
        let mut array = Vec::new();
        while !content.is_empty() {
            array.push(static_json(&content)?);
            if content.is_empty() {
                break;
            }
            content.parse::<Token![,]>()?;
        }
        return Ok(Value::Array(array));
    }
    let expression: Expr = input.parse()?;
    if let Expr::Lit(value) = &expression
        && let Lit::Bool(value) = &value.lit
    {
        return Ok(Value::Bool(value.value));
    }
    Ok(Value::String(brand_string(expression)?))
}

// 静态 json! 由标准 JSON 与窄品牌表达式解析器读取，动态资源实例通过 uriTemplate 表达。
#[derive(Default)]
struct Descriptors {
    resources: BTreeMap<String, Value>,
    prompts: BTreeMap<String, Value>,
    in_prompt_catalog: bool,
}

impl Descriptors {
    fn collect(&mut self, value: &Value) {
        match value {
            Value::Object(object) => {
                if let Some(uri) = object.get("uri").or_else(|| object.get("uriTemplate")).and_then(Value::as_str) {
                    self.resources.insert(uri.into(), value.clone());
                }
                if let Some(prompts) = object.get("prompts").and_then(Value::as_array) {
                    for prompt in prompts {
                        let name = prompt["name"].as_str().expect("missing prompt name");
                        assert!(self.prompts.insert(name.into(), prompt.clone()).is_none(), "duplicate prompt");
                    }
                }
                for child in object.values() {
                    self.collect(child);
                }
            }
            Value::Array(array) => {
                for child in array {
                    self.collect(child);
                }
            }
            _ => (),
        }
    }
}

impl<'ast> Visit<'ast> for Descriptors {
    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        let previous = self.in_prompt_catalog;
        self.in_prompt_catalog = function.sig.ident == "list_prompts";
        visit::visit_impl_item_fn(self, function);
        self.in_prompt_catalog = previous;
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !ast::is_test(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }
    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        if value.path.is_ident("vec") {
            // syn 不遍历宏内部的 token，将 vec! 参数按数组或重复表达式解析后继续访问。
            let tokens = &value.tokens;
            let expression = syn::parse2::<syn::Expr>(quote::quote!([#tokens]))
                .expect("unsupported vec! syntax; extend descriptor extraction");
            self.visit_expr(&expression);
        }
        if value.path.is_ident("json") {
            let tokens = value.tokens.to_string();
            match serde_json::from_str(&tokens).or_else(|_| static_json.parse2(value.tokens.clone())) {
                Ok(value) => self.collect(&value),
                Err(_) => {
                    assert!(!self.in_prompt_catalog, "nonliteral prompt catalog; extend descriptor extraction");
                    if tokens.contains("\"description\"")
                        && tokens.contains("\"mimeType\"")
                        && tokens.contains("\"uri\"")
                    {
                        assert!(
                            tokens.contains("format ! (\"memoswish://decks/{}\""),
                            "unsupported dynamic resource descriptor; add a static URI template"
                        );
                    }
                }
            }
        }
    }
}

pub fn assert_complete(catalog: &BTreeSet<String>, dispatch: &BTreeSet<String>, policy: &BTreeSet<String>) {
    assert_eq!(catalog, dispatch, "MCP catalog/dispatch names differ");
    assert_eq!(catalog, policy, "MCP catalog/OAuth permission policy names differ");
}

pub fn render(sources: &ast::Sources) -> String {
    let tools_source = sources.file("memoswish-mcp/src/tools.rs");
    let server_source = sources.file("memoswish-mcp/src/server.rs");
    let http_source = sources.file("memoswish-mcp/src/http.rs");
    let catalog = tools::list_tools_json();
    let tools = catalog["tools"].as_array().unwrap();
    let names: BTreeSet<_> = tools.iter().map(|t| t["name"].as_str().unwrap().into()).collect();
    assert_eq!(names.len(), tools.len(), "duplicate tool name");
    assert_complete(
        &names,
        &match_names(&tools_source.syntax, "name"),
        &match_names(&http_source.syntax, "params[\"name\"].as_str().unwrap_or(\"\")"),
    );
    let mut descriptors = Descriptors::default();
    descriptors.visit_file(&server_source.syntax);
    assert!(!descriptors.resources.is_empty(), "missing static resources");
    assert!(!descriptors.prompts.is_empty(), "missing static prompts");
    assert_eq!(descriptors.prompts.keys().cloned().collect::<BTreeSet<_>>(), prompt_dispatch(&server_source.syntax));
    let mut output = header("MCP 工具、资源与提示参考");
    output.push_str(&format!(
        "MCP 协商版本由 SDK handler 限定为 {}。HTTP 使用无会话管理器，不签发会话 ID，\
         认证后的 GET/HEAD/DELETE 返回 405，传入会话头被忽略。\
         版本、预算及安全边界见 [MCP 接口](../mcp.md#1-传输与认证)。\n\n",
        memoswish_mcp::protocol::SUPPORTED_VERSIONS.join("、")
    ));
    // 额外捕捉权限条件源码变化，避免新增参数条件落在当前参数组合之外。
    let policy = http_source
        .syntax
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "required_permissions" => Some(ast::text(&function.block)),
            _ => None,
        })
        .expect("missing OAuth permission function");
    output.push_str(&format!("<!-- OAuth 权限策略 SHA-256 {:x} -->\n\n", Sha256::digest(policy.as_bytes())));
    output.push_str(
        "工具来自实际 `tools/list`，包含参数 Schema、描述和注解。权限列调用 HTTP OAuth 预检函数，\
         各参数组合保留独立结果。OAuth 还要求当前角色允许这些权限。\
         JWT/API Token/stdio 的领域层权限检查与例外见 [MCP 认证边界](../mcp.md#1-传输与认证)。\n\n\
         条件权限回归见 [HTTP OAuth 测试](../../server/crates/memoswishd/src/oauth_tests.rs)，\
         工具、资源与提示行为见 [MCP 测试](../../server/crates/memoswish-mcp/src/server.rs)。\n\n\
         | 工具 | 说明 | 只读提示 | 破坏性提示 |\n| --- | --- | --- | --- |\n",
    );
    for tool in tools {
        output.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            tool["name"].as_str().unwrap(),
            cell(tool["description"].as_str().unwrap()),
            tool["annotations"]["readOnlyHint"],
            tool["annotations"]["destructiveHint"]
        ));
    }
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        output.push_str(&format!("\n## `{name}`\n\n| 参数组合 | OAuth 预检权限 |\n| --- | --- |\n"));
        let mut seen_permissions = BTreeSet::new();
        for (label, args) in [
            ("省略可选参数", json!({})),
            ("auto_tts=false", json!({"auto_tts": false})),
            ("commit=true", json!({"commit": true})),
            ("commit=true, auto_tts=false", json!({"commit": true, "auto_tts": false})),
            ("bgm={}", json!({"bgm": {}})),
            ("auto_tts=false, bgm={}", json!({"auto_tts": false, "bgm": {}})),
        ] {
            let permissions = scopes(json!({"method": "tools/call", "params": {"name": name, "arguments": args}}));
            if !seen_permissions.insert(permissions.clone()) {
                continue;
            }
            output.push_str(&format!("| `{label}` | {} |\n", permissions));
        }
        output.push_str(&format!("\n```json\n{}\n```\n", serde_json::to_string_pretty(tool).unwrap()));
    }
    output.push_str("\n## 资源\n\n`resources/list` 的 OAuth 预检权限为 ");
    output.push_str(&scopes(json!({"method": "resources/list"})));
    output.push_str("。每个卡组的动态 URI 由模板表示。\n\n| URI / 模板 | 名称 | MIME | 描述 | resources/read OAuth 权限 |\n| --- | --- | --- | --- | --- |\n");
    for (uri, descriptor) in descriptors.resources {
        output.push_str(&format!(
            "| `{uri}` | {} | `{}` | {} | {} |\n",
            cell(descriptor["name"].as_str().unwrap()),
            descriptor["mimeType"].as_str().unwrap(),
            cell(descriptor["description"].as_str().unwrap()),
            scopes(json!({"method": "resources/read", "params": {"uri": uri}}))
        ));
    }
    output.push_str("\n## 提示\n\n提示返回工作流文本。prompts/list 与 prompts/get 的 OAuth 预检权限为 ");
    output.push_str(&scopes(json!({"method": "prompts/get"})));
    output.push_str("，文本中提到的工具仍需各自授权。\n\n");
    for (name, descriptor) in descriptors.prompts {
        output.push_str(&format!(
            "### `{name}`\n\n```json\n{}\n```\n\n",
            serde_json::to_string_pretty(&descriptor).unwrap()
        ));
    }
    output.trim_end().to_string() + "\n"
}

fn prompt_dispatch(source: &syn::File) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for item in &source.items {
        if let syn::Item::Impl(item) = item
            && ast::text(&item.self_ty) == "McpServer"
        {
            for item in &item.items {
                if let syn::ImplItem::Fn(function) = item
                    && function.sig.ident == "get_prompt"
                {
                    let mut matches = MatchNames { target: "name".into(), ..Default::default() };
                    matches.visit_block(&function.block);
                    result = matches.names;
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod brand_tests {
    use super::*;

    #[test]
    fn branded_static_descriptors_use_compiled_names() {
        let descriptor = static_json
            .parse_str(r#"{"prompts":[{"description":concat!("Use ",env!("BRAND_EN_PRODUCT")),"required":true}]}"#)
            .unwrap();
        assert_eq!(descriptor["prompts"][0]["description"], format!("Use {}", env!("BRAND_EN_PRODUCT")));
        assert_eq!(descriptor["prompts"][0]["required"], true);
    }

    #[test]
    fn branded_descriptors_reject_other_environment_and_dynamic_expressions() {
        for source in [
            r#"{"description":env!("MEMOSWISH_JWT_SECRET")}"#,
            r#"{"description":format!("{}",secret)}"#,
            r#"{"description":unknown_value}"#,
        ] {
            assert!(static_json.parse_str(source).is_err());
        }
    }
}
