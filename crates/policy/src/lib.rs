//! Device-side policy of Pithagoras Sync: modes, folders, protected paths, approvals, audit.
//!
//! The device defends itself from the portal: everything here is set by the device
//! owner, and the portal can only make calls that this crate then judges.

pub mod approve;
pub mod audit;
pub mod config;
pub mod engine;
pub mod notify;
pub mod paths;
pub mod patterns;
pub mod protected;

pub use approve::{Answer, ApprovalRequest, Approver, BoxFuture, NoApprover};
pub use audit::{AuditLog, AuditRecord};
pub use config::{
    Access, DeviceConfig, Dirs, FolderGrant, FoldersShell, Mode, Policy, PortalConfig, Profile,
};
pub use engine::{
    Call, Clock, Confine, Engine, EngineOptions, Event, LandlockRules, Permit, Refusal, Request,
    system_clock,
};
