fn main() {
    // Only generate C headers for FFI feature
    #[cfg(feature = "ffi")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

        if let Ok(config) = cbindgen::Config::from_file("cbindgen.toml") {
            // Create include directory if not exists
            std::fs::create_dir_all("include").ok();

            if let Ok(bindings) = cbindgen::Builder::new()
                .with_crate(&crate_dir)
                .with_config(config)
                .generate()
            {
                bindings.write_to_file("include/xnt_ffi.h");
            }
        }
    }

    // napi-build for Node.js feature
    #[cfg(feature = "napi")]
    {
        napi_build::setup();
    }
}
