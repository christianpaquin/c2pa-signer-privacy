// Build script to provide missing __rust_probestack symbol for wasmer_vm

fn main() {
    // On some platforms, wasmer_vm needs the __rust_probestack symbol
    // which may not be available. We provide a stub implementation.
    
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=probestack.c");
    
    // Create a small C file with the probestack stub
    let probestack_code = r#"
// Stub for __rust_probestack
// This is a no-op implementation for platforms where it's not available
void __attribute__((naked)) __rust_probestack(void) {
    __asm__(
        "ret\n"
    );
}
"#;
    
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let probestack_path = std::path::Path::new(&out_dir).join("probestack.c");
    std::fs::write(&probestack_path, probestack_code).unwrap();
    
    // Compile the C file
    cc::Build::new()
        .file(&probestack_path)
        .compile("probestack");
}
