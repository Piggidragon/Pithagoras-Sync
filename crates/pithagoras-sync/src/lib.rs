//! Pithagoras Sync, phase 1: the background client without a GUI.

pub mod actions;
pub mod cli;
pub mod config_cmd;
pub mod control;
pub mod daemon;
pub mod dialogs;
pub mod gui;
pub mod install;
pub mod logfile;
pub mod owner;
pub mod purge;
#[cfg(windows)]
pub mod registry;
pub mod secrets;
pub mod setup;
pub mod update;
