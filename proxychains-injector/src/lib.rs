//! DLL injection utilities for proxychains-rs
//!
//! This crate provides platform-specific DLL injection functionality:
//! - Windows: Uses dll-syringe for DLL injection
//! - Unix: Stub implementation (not needed, uses LD_PRELOAD)

mod injector;

pub use injector::*;
