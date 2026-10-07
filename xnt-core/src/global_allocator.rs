//! jemalloc as the global allocator, for the node and prover binaries only.
//!
//! Included by `main.rs` and `bin/triton-vm-prover.rs` as a module of each
//! binary, never by `lib.rs`: a global allocator in the library would be forced
//! on everything built from it, including xnt-sdk's cdylib and Node.js module,
//! where a dlopen'ed jemalloc can fail to allocate its TLS. For the same reason
//! this does not use triton-vm's own `jemalloc` feature, which installs the
//! allocator in every artifact that links triton-vm.

/// The prover allocates and frees many large, short-lived buffers from many
/// threads; jemalloc handles this considerably better than the system
/// allocator. Triton VM measures proving about 10% faster on a 96-core machine.
/// jemalloc is built from C sources and only known to build on these
/// platforms, matching triton-vm v9's `jemalloc` feature.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc's configuration, read at startup, copied from triton-vm v9.
/// Transparent huge pages save the page faults that dominate the prover's
/// large buffers (about 10% faster for small proofs, 15% for large ones); the
/// background thread purges unused memory off the allocating threads; capping
/// the arenas bounds idle memory on machines with many threads. The
/// environment variable `_RJEM_MALLOC_CONF` overrides this.
#[cfg(target_os = "linux")]
#[unsafe(export_name = "_rjem_malloc_conf")]
static JEMALLOC_CONF: &[u8] = b"thp:always,metadata_thp:always,background_thread:true,narenas:32\0";
