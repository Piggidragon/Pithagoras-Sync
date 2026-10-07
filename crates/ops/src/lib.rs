//! Device-side operations of Pithagoras Sync: files, grep, find, exec.
//!
//! Everything here runs only after the policy engine allowed the call; the
//! `Permit` it returned says where (resolved path, folder root) and how (Landlock).

#[cfg(target_os = "linux")]
pub mod cgroup;
pub mod env;
pub mod exec;
pub mod fsops;
pub mod info;
pub mod search;
pub mod shim;

/// A Job Object with kill-on-close: what commands run in, and the computer-use
/// servers too.
#[cfg(windows)]
pub use exec::win::Job;
pub use exec::{ExecConfig, ExecOutcome, Execs};
pub use shim::{SHIM_ARG, shim_main};

/// Whether the Folders shell can run under Landlock on this machine.
pub fn landlock_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        shim::landlock::abi_version().is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
