use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use syn::visit::{self, Visit};
use syn::{Expr, GenericArgument, PathArguments, Type};

use super::{ast, cell, header};

#[derive(Default)]
pub struct Environment {
    pub mappings: BTreeMap<String, String>,
    aliases: BTreeMap<String, String>,
}

impl Environment {
    fn target(&self, value: &Expr) -> String {
        let value = match value {
            Expr::Reference(value) => value.expr.as_ref(),
            value => value,
        };
        let mut path = ast::text(value).replace(' ', "");
        for (alias, target) in &self.aliases {
            if let Some(tail) = path.strip_prefix(&format!("{alias}.")) {
                path = format!("{target}.{tail}");
                break;
            }
        }
        path.strip_prefix("self.").unwrap_or(&path).into()
    }
}

impl<'ast> Visit<'ast> for Environment {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(initializer)) = (&local.pat, &local.init)
            && let Expr::Reference(value) = initializer.expr.as_ref()
        {
            let target = self.target(&value.expr);
            self.aliases.insert(pattern.ident.to_string(), target);
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        // 条件中的 var 调用是环境来源，错误上下文中的同名字符串不参与匹配。
        let mut names = ast::Strings::default();
        names.visit_expr(&expression.cond);
        if !names.0.is_empty() {
            let mut assignments = Assignments::default();
            assignments.visit_block(&expression.then_branch);
            for name in names.0 {
                assert!(
                    name.chars().all(|v| v.is_ascii_uppercase() || v.is_ascii_digit() || v == '_'),
                    "unexpected env name {name}"
                );
                let targets: BTreeSet<_> = assignments.0.iter().map(|target| self.target(target)).collect();
                assert_eq!(targets.len(), 1, "environment {name} must map to one configuration key");
                self.mappings.insert(name, targets.into_iter().next().unwrap());
            }
        }
        visit::visit_expr_if(self, expression);
    }

    fn visit_expr_tuple(&mut self, tuple: &'ast syn::ExprTuple) {
        if tuple.elems.len() == 2
            && let Some(name) = ast::string(&tuple.elems[0])
            && name.starts_with("MEMOSWISH_")
        {
            self.mappings.insert(name, self.target(&tuple.elems[1]));
        }
        visit::visit_expr_tuple(self, tuple);
    }
}

#[derive(Default)]
struct Assignments<'ast>(Vec<&'ast Expr>);
impl<'ast> Visit<'ast> for Assignments<'ast> {
    fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
        self.0.push(&assignment.left);
        visit::visit_expr_assign(self, assignment);
    }
}

fn inner_type(ty: &Type) -> (String, bool) {
    let Type::Path(path) = ty else { panic!("unsupported configuration type") };
    let last = path.path.segments.last().unwrap();
    let name = last.ident.to_string();
    if name == "Vec" || name == "Option" {
        let PathArguments::AngleBracketed(args) = &last.arguments else { panic!("missing type argument") };
        let GenericArgument::Type(inner) = &args.args[0] else { panic!("unsupported type argument") };
        return (inner_type(inner).0, name == "Vec");
    }
    (name, false)
}

// 此入口只能接收合成默认值，绝不调用 Config::load、apply_env 或 AppState::build。
fn array_default(name: &str) -> Value {
    match name {
        "OidcProvider" => serde_json::to_value(memoswish_auth::oidc_config::OidcProvider::default()).unwrap(),
        "HttpTtsConfig" => serde_json::to_value(memoswish_media::tts::http::HttpTtsConfig::default()).unwrap(),
        "CommandTtsConfig" => serde_json::to_value(
            serde_json::from_value::<memoswish_media::tts::command::CommandTtsConfig>(json!({"program": ""})).unwrap(),
        )
        .unwrap(),
        "PreRegisteredClient" => Value::Null,
        _ => panic!("missing synthetic array default for {name}; extend the generator"),
    }
}

pub fn secret(path: &str) -> bool {
    if matches!(path, "smtp.password" | "smtp.username") {
        return true;
    }
    let key = path.rsplit('.').next().unwrap();
    ["secret", "api_key", "encryption_key", "private_key", "access_key_id", "database_url", "redis_url"]
        .iter()
        .any(|part| key.contains(part))
}

pub fn safe_default(path: &str, value: &Value) -> String {
    if secret(path) { "<secret; never resolved>".into() } else { value.to_string() }
}

fn serde_default(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().filter(|attribute| attribute.path().is_ident("serde")).any(|attribute| {
        let metadata = attribute
            .parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
            .unwrap();
        metadata.iter().any(|meta| meta.path().is_ident("default"))
    })
}

struct Configuration<'a> {
    structures: BTreeMap<String, (&'a str, &'a syn::ItemStruct)>,
    environment: BTreeMap<String, String>,
    keys: Vec<String>,
    output: String,
}

impl Configuration<'_> {
    fn walk(&mut self, name: &str, prefix: &str, defaults: &Value, inherited: &str, array_element: bool) {
        let (source, definition) = *self.structures.get(name).unwrap_or_else(|| panic!("missing config type {name}"));
        let container_default = serde_default(&definition.attrs);
        for field in &definition.fields {
            let key = field.ident.as_ref().unwrap().to_string();
            let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
            let (child, array) = inner_type(&field.ty);
            let condition = ast::condition(&field.attrs).unwrap_or_else(|| inherited.into());
            let value = defaults.get(&key).unwrap_or(&Value::Null);
            if self.structures.contains_key(&child) && !array {
                self.walk(&child, &path, value, &condition, array_element);
                continue;
            }
            let has_default = container_default || serde_default(&field.attrs);
            let default = if array_element && !has_default && !secret(&path) {
                "<required>".into()
            } else {
                safe_default(&path, value)
            };
            let env: Vec<_> =
                self.environment.iter().filter(|(_, target)| *target == &path).map(|(name, _)| name.as_str()).collect();
            self.keys.push(path.clone());
            self.output.push_str(&format!(
                "| `{path}` | `{}` | `{}` | {} | {} | {} |\n",
                cell(ast::text(&field.ty)),
                cell(default),
                if env.is_empty() { "—".into() } else { format!("`{}`", env.join("`, `")) },
                cell(&condition),
                ast::link(source)
            ));
            if array && self.structures.contains_key(&child) {
                self.walk(&child, &format!("{path}[]"), &array_default(&child), &condition, true);
            }
        }
    }
}

pub fn render(sources: &ast::Sources) -> String {
    let config = sources.file("memoswishd/src/config.rs");
    let mut environment = Environment::default();
    for item in &config.syntax.items {
        if let syn::Item::Impl(item) = item {
            for item in &item.items {
                if let syn::ImplItem::Fn(function) = item
                    && ["apply_env", "apply_object_store_env"].contains(&function.sig.ident.to_string().as_str())
                {
                    environment.visit_block(&function.block);
                }
            }
        }
    }
    for item in &sources.file("memoswishd/src/config/environment.rs").syntax.items {
        if let syn::Item::Const(item) = item
            && item.ident == "ALIASES"
        {
            let Expr::Reference(reference) = item.expr.as_ref() else { panic!("expected alias array") };
            let Expr::Array(array) = reference.expr.as_ref() else { panic!("expected alias array") };
            for entry in &array.elems {
                let Expr::Tuple(tuple) = entry else { panic!("expected alias tuple") };
                let name = ast::string(&tuple.elems[0]).expect("alias name");
                let path = ast::string(&tuple.elems[1]).expect("alias target");
                assert!(environment.mappings.insert(name, path).is_none());
            }
            environment.mappings.insert("DATABASE_URL".into(), "database_url".into());
        }
    }
    let mut reference = Configuration {
        structures: sources.structures(),
        environment: environment.mappings,
        keys: vec![],
        output: header("配置与环境变量参考"),
    };
    reference.output.push_str(
        "键与类型来自 Rust 配置结构，值来自合成默认实例。数组本身的默认值与数组元素的默认值分开列出，\
         `<required>` 表示元素的必填字段。秘密字段统一标记，不读取环境、配置文件、密钥文件或生效配置。\n\n\
         功能条件来自配置字段旁的元数据，启动校验见 [组装入口](../../server/crates/memoswishd/src/app.rs)。\n\n\
         | 键 | Rust 类型 | 默认值 | 环境变量 | 使用条件 | 来源 |\n| --- | --- | --- | --- | --- | --- |\n",
    );
    reference.walk("Config", "", &serde_json::to_value(crate::config::Config::default()).unwrap(), "所有构建", false);
    reference.output.push_str("\n## 环境覆盖映射\n\n同一目标的变量按代码顺序优先选取。`MEMOSWISH_DATABASE_URL` 优先于 `DATABASE_URL`。JSON 变量覆盖整个数组。\n\n| 环境变量 | 目标键 |\n| --- | --- |\n");
    for (name, target) in &reference.environment {
        assert!(reference.keys.contains(target), "unknown environment target {name} -> {target}");
        reference.output.push_str(&format!("| `{name}` | `{target}` |\n"));
    }
    reference.output.push_str("\n## CLI 与日志环境入口\n\n名称来自 Clap 参数属性及实际 EnvFilter 默认环境入口，Token 字段仅列出名称。\n\n| 环境变量 | CLI / 日志字段 |\n| --- | --- |\n");
    let mut cli = CliEnvironment::default();
    cli.visit_file(&sources.file("memoswishd/src/main.rs").syntax);
    for (name, field) in cli.0 {
        reference.output.push_str(&format!("| `{name}` | `{field}` |\n"));
    }
    reference.output.push_str(
        "\n## 保留维护策略文件\n\n\
         `retention-sweep --policy` 读取独立 JSON，以下字段均为必填，不属于 daemon TOML 或环境覆盖。\
         未知字段、版本及越界期限会拒绝；不从隐私合同占位符推导默认期限。\n\n\
         | 键 | Rust 类型 | 默认值 | 环境变量 | 使用条件 | 来源 |\n\
         | --- | --- | --- | --- | --- | --- |\n",
    );
    reference.walk("RetentionPolicy", "", &Value::Null, "embedded 或 maintenance；显式策略文件", true);
    reference.output
}

#[derive(Default)]
struct CliEnvironment(BTreeMap<String, String>);
impl<'ast> Visit<'ast> for CliEnvironment {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if ast::text(&call.func).replace(' ', "") == "EnvFilter::try_from_default_env" {
            self.0.insert(tracing_subscriber::EnvFilter::DEFAULT_ENV.into(), "EnvFilter".into());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        for attribute in &field.attrs {
            if attribute.path().is_ident("arg") {
                attribute
                    .parse_nested_meta(|meta| {
                        if meta.path.is_ident("env") {
                            let name: syn::LitStr = meta.value()?.parse()?;
                            self.0.insert(name.value(), field.ident.as_ref().unwrap().to_string());
                        } else if meta.input.peek(syn::Token![=]) {
                            let _: Expr = meta.value()?.parse()?;
                        }
                        Ok(())
                    })
                    .unwrap();
            }
        }
    }
}
