//! Embed generated assets into the binary when present. Missing UI dist or
//! eBPF object keeps development builds working; release packaging builds both
//! first so the installed binary is self-contained.

use std::{env, fs, path::Path};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set");
    compile_proto(&manifest);
    let ui_dist = Path::new(&manifest).join("../ui/dist");
    println!("cargo:rerun-if-changed={}", ui_dist.display());
    let ebpf_object =
        Path::new(&manifest).join("../target/bpfel-unknown-none/release/edge-lb-ebpf");
    println!("cargo:rerun-if-changed={}", ebpf_object.display());
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR set");
    let dest = Path::new(&out_dir).join("ui_files.rs");
    let ebpf_dest = Path::new(&out_dir).join("embedded_ebpf.rs");
    let dist = ui_dist;

    let mut entries: Vec<(String, String, Vec<u8>)> = Vec::new(); // (path, mime, bytes)
    if dist.is_dir() {
        collect(&dist, &dist, &mut entries);
    }
    let mut code = String::from("pub static UI_FILES: &[(&str, &str, &[u8])] = &[\n");
    for (path, mime, bytes) in &entries {
        code.push_str(&format!("    ({path:?}, {mime:?}, &{:?}),\n", bytes));
    }
    code.push_str("];\n");
    code.push_str(
        "pub fn find_ui_file(path: &str) -> Option<(String, &'static [u8])> {\n\
         let path = path.trim_start_matches('/');\n\
         let path = if path.is_empty() { \"index.html\" } else { path };\n\
         let found = UI_FILES.iter().find(|(p, _, _)| *p == path)\n\
         .or_else(|| UI_FILES.iter().find(|(p, _, _)| *p == \"index.html\"))?;\n\
         Some((found.1.to_string(), found.2))\n\
         }\n",
    );
    fs::write(&dest, code).expect("writing ui_files.rs");

    let ebpf_code = if ebpf_object.exists() {
        format!(
            "pub static EMBEDDED_EBPF: &[u8] = include_bytes!(r#\"{}\"#);\n\
             pub fn embedded_ebpf() -> Option<&'static [u8]> {{ Some(EMBEDDED_EBPF) }}\n",
            ebpf_object.display()
        )
    } else {
        "pub fn embedded_ebpf() -> Option<&'static [u8]> { None }\n".to_string()
    };
    fs::write(&ebpf_dest, ebpf_code).expect("writing embedded_ebpf.rs");
}

fn compile_proto(manifest: &str) {
    let proto = Path::new(manifest).join("proto/control.proto");
    let include = Path::new(manifest).join("proto");
    println!("cargo:rerun-if-changed={}", proto.display());

    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
        // Build scripts run single-threaded for this process; this only scopes
        // prost-build's protoc lookup for the current build.
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    tonic_prost_build::configure()
        .compile_protos(&[proto], &[include])
        .expect("compile edge-lb control proto");
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, String, Vec<u8>)>) {
    let Ok(iter) = fs::read_dir(dir) else {
        return;
    };
    for entry in iter.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out);
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let mime = mime_for(&rel);
            if let Ok(bytes) = fs::read(&path) {
                out.push((rel, mime, bytes));
            }
        }
    }
}

fn mime_for(path: &str) -> String {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "map" => "application/json",
        _ => "application/octet-stream",
    }
    .to_string()
}
