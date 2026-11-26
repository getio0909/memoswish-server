use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::visit::Visit;
use syn::{Attribute, Expr, ItemStruct, Lit};

pub struct Source {
    pub path: String,
    pub syntax: syn::File,
}

pub struct Sources {
    pub files: Vec<Source>,
}

impl Sources {
    pub fn load(root: &Path) -> Self {
        fn collect(directory: &Path, paths: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect(&path, paths);
                } else if path.extension().is_some_and(|v| v == "rs") {
                    paths.push(path);
                }
            }
        }
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(root.join("server/crates")).unwrap() {
            collect(&entry.unwrap().path().join("src"), &mut paths);
        }
        paths.sort();
        Self {
            files: paths
                .into_iter()
                .filter(|path| {
                    let stem = path.file_stem().unwrap().to_str().unwrap();
                    !["test", "tests", "conformance"].contains(&stem)
                        && !stem.ends_with("_test")
                        && !stem.ends_with("_tests")
                })
                .map(|path| Source {
                    path: path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                    syntax: syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap(),
                })
                .collect(),
        }
    }

    pub fn file(&self, suffix: &str) -> &Source {
        self.files.iter().find(|f| f.path.ends_with(suffix)).unwrap()
    }

    pub fn structures(&self) -> BTreeMap<String, (&str, &ItemStruct)> {
        let mut result = BTreeMap::new();
        for file in &self.files {
            for item in &file.syntax.items {
                if let syn::Item::Struct(item) = item {
                    // 仅可达配置类型会被使用。当前结构名在这些类型中唯一。
                    result.insert(item.ident.to_string(), (file.path.as_str(), item));
                }
            }
        }
        result
    }

    pub fn module_conditions(&self, source: &str) -> String {
        let path = Path::new(source);
        let directory = path.parent().unwrap();
        let module = path.file_stem().unwrap().to_str().unwrap();
        let mut conditions = Vec::new();
        for file in &self.files {
            let parent = Path::new(&file.path);
            if parent.parent() == Some(directory)
                && ["main", "lib"].contains(&parent.file_stem().unwrap().to_str().unwrap())
            {
                for item in &file.syntax.items {
                    if let syn::Item::Mod(item) = item
                        && item.ident == module
                    {
                        conditions.extend(item.attrs.iter().filter(|a| a.path().is_ident("cfg")).map(text));
                    }
                }
            }
        }
        conditions.join("，")
    }
}

pub fn text(node: &impl ToTokens) -> String {
    node.to_token_stream().to_string()
}

pub fn string(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Lit(value) => match &value.lit {
            Lit::Str(value) => Some(value.value()),
            _ => None,
        },
        _ => None,
    }
}

pub fn docs(attributes: &[Attribute]) -> String {
    attributes
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .filter_map(|attr| match &attr.meta {
            syn::Meta::NameValue(value) => string(&value.value),
            _ => None,
        })
        .map(|v| v.trim().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn condition(attributes: &[Attribute]) -> Option<String> {
    let docs = docs(attributes);
    docs.split_once("参考条件：").map(|(_, v)| v.trim_end_matches('。').to_string())
}

pub fn is_test(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|a| a.path().is_ident("cfg") && text(a).contains("test"))
}

pub fn link(path: &str) -> String {
    format!("[源码](../../{path})")
}

#[derive(Default)]
pub struct Strings(pub Vec<String>);

impl<'ast> Visit<'ast> for Strings {
    fn visit_lit_str(&mut self, value: &'ast syn::LitStr) {
        self.0.push(value.value());
    }
}
