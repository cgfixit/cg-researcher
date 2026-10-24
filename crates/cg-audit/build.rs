// Compiles the .proto with protox (pure Rust), so no `protoc` binary is needed.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/cg_audit.proto");
    let fds = protox::compile(["proto/cg_audit.proto"], ["proto"])?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
