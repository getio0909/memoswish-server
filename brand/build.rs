use std::{env, fs, path::PathBuf};

fn html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn main() {
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory is required"),
    );
    let source = manifest.join("../../../brand/names.json");
    println!("cargo::rerun-if-changed={}", source.display());
    let names: serde_json::Value =
        serde_json::from_slice(&fs::read(source).expect("Brand data is required"))
            .expect("Brand data must be valid JSON");
    for locale in ["en", "zh"] {
        for field in ["product", "commercial"] {
            let value = names[locale][field]
                .as_str()
                .expect("Brand names must be strings");
            assert!(
                !value.trim().is_empty() && !value.contains(['\n', '\r']),
                "Brand names must be nonempty single lines"
            );
            if field == "commercial" {
                assert!(
                    value.matches("{name}").count() == 1,
                    "Commercial name must contain one name placeholder"
                );
            }
            println!(
                "cargo::rustc-env=BRAND_{}_{}={value}",
                locale.to_uppercase(),
                field.to_uppercase()
            );
        }
    }
    let admin = manifest.join("src/admin.html");
    if admin.exists() {
        println!("cargo::rerun-if-changed={}", admin.display());
        let rendered = fs::read_to_string(admin)
            .expect("Admin template is required")
            .replace(
                "{{product_en}}",
                &html(names["en"]["product"].as_str().unwrap()),
            )
            .replace(
                "{{product_zh}}",
                &html(names["zh"]["product"].as_str().unwrap()),
            );
        fs::write(
            PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("admin.html"),
            rendered,
        )
        .expect("Cannot write branded admin page");
    }
}
