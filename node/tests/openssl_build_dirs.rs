//! The node links a vendored OpenSSL (openssl-src). OpenSSL compiles its install directories into
//! libcrypto as ENGINESDIR and MODULESDIR. By default those are under the cargo target dir of the
//! machine that built it, which ties the node's bytes to the build root and names a directory that
//! does not exist where the node runs. `.cargo/config.toml` fixes both under OPENSSLDIR.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

// include/openssl/crypto.h
const OPENSSL_DIR: c_int = 4;
const OPENSSL_ENGINES_DIR: c_int = 5;
const OPENSSL_MODULES_DIR: c_int = 8;

extern "C" {
    fn OpenSSL_version(t: c_int) -> *const c_char;
}

fn version_field(t: c_int) -> String {
    // Links libcrypto through the node's own openssl dependency.
    let _ = openssl::version::number();
    // SAFETY: OpenSSL_version returns a pointer to a static NUL-terminated string for every type.
    unsafe { CStr::from_ptr(OpenSSL_version(t)) }
        .to_string_lossy()
        .into_owned()
}

#[test]
fn linked_openssl_directories_do_not_name_the_build_tree() {
    let engines = version_field(OPENSSL_ENGINES_DIR);
    let modules = version_field(OPENSSL_MODULES_DIR);
    for (name, v) in [("ENGINESDIR", &engines), ("MODULESDIR", &modules)] {
        assert!(
            !v.contains("/target/") && !v.contains("openssl-build"),
            "{name} names the build tree: {v}"
        );
    }
    assert_eq!(engines, "ENGINESDIR: \"/usr/local/ssl/lib/engines-3\"");
    assert_eq!(modules, "MODULESDIR: \"/usr/local/ssl/lib/ossl-modules\"");
}

#[test]
fn linked_openssl_keeps_its_default_openssldir() {
    // The fixed directories sit under OPENSSLDIR, the directory the node already trusts.
    assert_eq!(version_field(OPENSSL_DIR), "OPENSSLDIR: \"/usr/local/ssl\"");
}
