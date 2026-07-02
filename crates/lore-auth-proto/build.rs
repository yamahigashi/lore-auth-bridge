fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    // SAFETY: this build script is single-threaded, and prost-build reads PROTOC
    // during the following compile step.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    let proto_root = "../../third_party/lore-proto/proto";
    let protos = [
        "../../third_party/lore-proto/proto/epicurc/auth_api.proto",
        "../../third_party/lore-proto/proto/ucsauth/rebac_api.proto",
    ];

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &[proto_root])?;

    println!("cargo:rerun-if-changed={proto_root}/epicurc/auth_api.proto");
    println!("cargo:rerun-if-changed={proto_root}/ucsauth/rebac_api.proto");

    Ok(())
}
