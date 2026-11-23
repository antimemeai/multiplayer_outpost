//! Deterministic build identity generator (`OUTPOST_BUILD_DIGEST_HEX` and `OUTPOST_BUILD_ORDER`).
//!
//! Computes SHA-256 over workspace `Cargo.lock` + sorted `crates/*/src/**` + `TARGET` + `PROFILE`.
//! Never embeds random values or `LC_UUID`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=OUTPOST_BUILD_ORDER");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()),
    );
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(&manifest_dir)
        .to_path_buf();

    let mut hasher = Sha256::new();

    let target = env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown-profile".to_string());
    hasher.update(b"TARGET:");
    hasher.update(target.as_bytes());
    hasher.update(b"\nPROFILE:");
    hasher.update(profile.as_bytes());
    hasher.update(b"\n");

    // Hash workspace Cargo.lock if present.
    let lock_path = workspace_root.join("Cargo.lock");
    if lock_path.is_file() {
        println!("cargo:rerun-if-changed={}", lock_path.display());
        if let Ok(bytes) = fs::read(&lock_path) {
            hasher.update(b"LOCK:");
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
    }

    // Collect and sort all files under crates/*/src/** deterministically.
    let crates_dir = workspace_root.join("crates");
    let mut source_files: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = fs::read_dir(&crates_dir) {
        let mut crate_dirs: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        crate_dirs.sort();
        for cdir in crate_dirs {
            let src_dir = cdir.join("src");
            if src_dir.is_dir() {
                collect_files_sorted(&src_dir, &mut source_files);
            }
        }
    }
    source_files.sort();

    for file_path in source_files {
        println!("cargo:rerun-if-changed={}", file_path.display());
        let rel = file_path
            .strip_prefix(&workspace_root)
            .unwrap_or(&file_path)
            .to_string_lossy();
        if let Ok(bytes) = fs::read(&file_path) {
            hasher.update(b"FILE:");
            hasher.update(rel.as_bytes());
            hasher.update(b"\0");
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
    }

    let digest = hasher.finalize();
    let hex = to_lower_hex(&digest);
    println!("cargo:rustc-env=OUTPOST_BUILD_DIGEST_HEX={hex}");

    // Deterministic monotonic build order: explicit env override or semantic version integer.
    let build_order: u64 = env::var("OUTPOST_BUILD_ORDER")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or_else(|| {
            let major: u64 = env::var("CARGO_PKG_VERSION_MAJOR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let minor: u64 = env::var("CARGO_PKG_VERSION_MINOR")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            let patch: u64 = env::var("CARGO_PKG_VERSION_PATCH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            (major * 1_000_000 + minor * 1_000 + patch).max(1)
        });
    println!("cargo:rustc-env=OUTPOST_BUILD_ORDER={build_order}");
}

fn collect_files_sorted(dir: &Path, out: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect_files_sorted(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

fn to_lower_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Minimal pure-Rust FIPS 180-4 SHA-256 implementation (zero build-dependencies).
struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        if self.buf_len > 56 {
            let pad = 64 - self.buf_len;
            self.update(&vec![0u8; pad]);
        }
        let pad = 56 - self.buf_len;
        self.update(&vec![0u8; pad]);
        self.update(&bit_len.to_be_bytes());
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            *slot = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for (&ki, &wi) in Self::K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(ki)
                .wrapping_add(wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
