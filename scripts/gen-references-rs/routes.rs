use std::collections::BTreeSet;

use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall};

use super::{ast, cell, header};

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Route {
    pub path: String,
    pub methods: String,
    pub handler: String,
    pub condition: String,
    pub source: String,
}

pub struct Inventory {
    pub routes: BTreeSet<Route>,
    source: String,
    pub condition: String,
}

impl Inventory {
    pub fn new(source: &str) -> Self {
        Self { routes: BTreeSet::new(), source: source.into(), condition: "所有构建".into() }
    }
}

fn methods(expression: &Expr, result: &mut Vec<(String, String)>) {
    let (name, arguments) = match expression {
        Expr::Call(call) => {
            let Expr::Path(path) = call.func.as_ref() else { panic!("unsupported route factory") };
            (path.path.segments.last().unwrap().ident.to_string(), &call.args)
        }
        Expr::MethodCall(call) => {
            methods(&call.receiver, result);
            (call.method.to_string(), &call.args)
        }
        _ => panic!("unsupported method router: {}", ast::text(expression)),
    };
    if ["layer", "route_layer"].contains(&name.as_str()) {
        return;
    }
    assert!(
        ["get", "head", "post", "put", "patch", "delete", "options", "trace", "connect"].contains(&name.as_str()),
        "unsupported route method {name}; extend the generator before adding this routing form"
    );
    let handler = ast::text(arguments.first().expect("missing handler"));
    result.push((name.to_uppercase(), handler.clone()));
    if name == "get" {
        result.push(("HEAD".into(), format!("{handler}（GET 自动提供）")));
    }
}

impl<'ast> Visit<'ast> for Inventory {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !ast::is_test(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if ast::is_test(&item.attrs) {
            return;
        }
        let previous = self.condition.clone();
        if let Some(condition) = ast::condition(&item.attrs) {
            self.condition = format!("{}，{}", self.condition, condition);
        }
        for attribute in item.attrs.iter().filter(|a| a.path().is_ident("cfg")) {
            self.condition = format!("{}，{}", self.condition, ast::text(attribute));
        }
        visit::visit_item_fn(self, item);
        self.condition = previous;
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let previous = self.condition.clone();
        self.condition = format!("{}，if {}", previous, ast::text(&expression.cond));
        self.visit_block(&expression.then_branch);
        self.condition = previous.clone();
        if let Some((_, branch)) = &expression.else_branch {
            self.condition = format!("{}，else {}", previous, ast::text(&expression.cond));
            self.visit_expr(branch);
        }
        self.condition = previous;
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        // 动态宿主路由不属于公开核心端点，仅允许固定扩展前缀和具名宿主输入。
        let host_extension = name == "nest"
            && self.source == "server/crates/memoswishd/src/runtime.rs"
            && ast::text(&call.receiver) == "app"
            && call.args.len() == 2
            && ast::string(&call.args[0]).as_deref() == Some("/extensions")
            && ast::text(&call.args[1]) == "routes";
        assert!(
            host_extension || !["nest", "nest_service", "route_service"].contains(&name.as_str()),
            "unsupported routing form {name} in {}; extend inventory extraction",
            self.source
        );
        if name == "route" {
            assert_eq!(call.args.len(), 2, "unsupported route arity");
            let path = ast::string(&call.args[0]).expect("route path must be a literal; extend inventory extraction");
            let mut handlers = Vec::new();
            methods(&call.args[1], &mut handlers);
            // 显式 HEAD 覆盖 Axum 的隐式 HEAD。
            if handlers.iter().any(|(method, handler)| method == "HEAD" && !handler.contains("GET 自动提供")) {
                handlers.retain(|(_, handler)| !handler.contains("GET 自动提供"));
            }
            for (method, handler) in handlers {
                assert!(
                    self.routes.insert(Route {
                        path: path.clone(),
                        methods: method,
                        handler,
                        condition: self.condition.clone(),
                        source: self.source.clone(),
                    }),
                    "duplicate route registration"
                );
            }
        }
        visit::visit_expr_method_call(self, call);
    }
}

pub fn render(sources: &ast::Sources) -> String {
    let mut routes = BTreeSet::new();
    for source in &sources.files {
        let mut inventory = Inventory::new(&source.path);
        let conditions = sources.module_conditions(&source.path);
        if !conditions.is_empty() {
            inventory.condition = conditions;
        }
        inventory.visit_file(&source.syntax);
        routes.extend(inventory.routes);
    }
    assert!(!routes.is_empty(), "empty route inventory");
    let mut output = header("HTTP 端点参考");
    output.push_str(
        "路径、方法和 handler 从 Rust 路由表达式提取，运行条件取自注册函数旁的元数据。\n\n\
         GET 包含 Axum 自动提供的 HEAD。通配兜底也列入清单。注册不代表调用一定成功，\
         例如关闭动态注册后 `/oauth/register` 仍注册，具体响应由 handler 决定。\n\n\
         认证与错误行为见 [协议](../protocol.md)、[MCP](../mcp.md)，\
         行为测试见 [REST](../../server/crates/memoswishd/src/tests.rs)、\
         [OAuth](../../server/crates/memoswishd/src/oauth_tests.rs)、\
         [OIDC](../../server/crates/memoswishd/src/oidc_tests.rs) 和\
         [MCP HTTP](../../server/crates/memoswish-mcp/src/http.rs)。\n\n\
         | 方法 | 路径 | Handler | 注册条件 | 来源 |\n| --- | --- | --- | --- | --- |\n",
    );
    for route in routes {
        output.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} |\n",
            route.methods,
            route.path,
            cell(route.handler),
            cell(route.condition),
            ast::link(&route.source)
        ));
    }
    output.push_str("\n## 挂载条件\n\n以下条件直接提取自 API 组装分支，保留编译属性。运行配置校验见 [AppState](../../server/crates/memoswishd/src/app.rs)。\n\n| 条件表达式 | 编译属性 |\n| --- | --- |\n");
    let mut mounts = Mounts::default();
    mounts.visit_file(&sources.file("memoswishd/src/api.rs").syntax);
    output.push_str(&mounts.0);
    output
}

#[derive(Default)]
struct Mounts(String);
impl<'ast> Visit<'ast> for Mounts {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        if ast::text(&expression.then_branch).contains("router (") {
            let attributes = expression.attrs.iter().map(ast::text).collect::<Vec<_>>().join(" ");
            self.0.push_str(&format!("| `{}` | `{}` |\n", cell(ast::text(&expression.cond)), cell(attributes)));
        }
        visit::visit_expr_if(self, expression);
    }
}
