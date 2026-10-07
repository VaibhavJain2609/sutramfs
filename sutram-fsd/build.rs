fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/sutramfs.proto")?;
    println!("cargo:rerun-if-changed=proto/sutramfs.proto");
    Ok(())
}
