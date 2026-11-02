// SPDX-FileCopyrightText: 2026 Timothy Redaelli <timothy.redaelli@gmail.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The WinFsp DLL lives in the WinFsp install directory, not on the DLL
//! search path, so it is delay loaded: `winfsp_wrs::init` loads it from
//! there before the first call into it.

fn main() {
    // MSVC only: MinGW linkers have no delay loading.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    let dll = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "winfsp-x64.dll",
        Ok("aarch64") => "winfsp-a64.dll",
        Ok("x86") => "winfsp-x86.dll",
        _ => panic!("unsupported Windows architecture"),
    };
    println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
    // The test harness of the binary does not call into WinFsp, so the
    // linker warns that the delay load is unused.
    println!("cargo:rustc-link-arg-bins=/IGNORE:4199");
    println!("cargo:rustc-link-lib=dylib=delayimp");
}
