//! Bitcoin Inquisition binary management.
//!
//! Downloads and caches the Bitcoin Inquisition binary for regtest testing.
//! Inquisition provides CTV (BIP-119) support on regtest and custom signet.

use std::path::{Path, PathBuf};

/// Bitcoin Inquisition release information.
pub struct InquisitionRelease {
    pub version: &'static str,
    pub url_base: &'static str,
}

/// Default Inquisition release for testing.
pub const DEFAULT_RELEASE: InquisitionRelease = InquisitionRelease {
    version: "28.0",
    url_base: "https://github.com/bitcoin-inquisition/bitcoin/releases/download",
};

/// Get the expected binary path in the cache directory.
pub fn binary_path(cache_dir: &Path) -> PathBuf {
    cache_dir
        .join("bitcoin-inquisition")
        .join("bin")
        .join("bitcoind")
}

/// Get the download URL for the current platform.
pub fn download_url(release: &InquisitionRelease) -> String {
    let platform = if cfg!(target_os = "linux") {
        if cfg!(target_arch = "x86_64") {
            "x86_64-linux-gnu"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-linux-gnu"
        } else {
            "x86_64-linux-gnu" // fallback
        }
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "arm64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        }
    } else {
        "x86_64-linux-gnu" // fallback
    };

    format!(
        "{}/inq-v{}/bitcoin-inquisition-{}-{}.tar.gz",
        release.url_base, release.version, release.version, platform
    )
}

/// Check if the Inquisition binary is available.
pub fn is_available(cache_dir: &Path) -> bool {
    binary_path(cache_dir).exists()
}

/// Find the bitcoind binary, checking in order:
/// 1. SOVPOOL_BITCOIND env var
/// 2. Cache directory
/// 3. System PATH
pub fn find_bitcoind(cache_dir: &Path) -> Option<PathBuf> {
    // 1. Environment variable
    if let Ok(path) = std::env::var("SOVPOOL_BITCOIND") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // 2. Cache directory
    let cached = binary_path(cache_dir);
    if cached.exists() {
        return Some(cached);
    }

    // 3. System PATH
    if let Ok(output) = std::process::Command::new("which").arg("bitcoind").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    None
}
