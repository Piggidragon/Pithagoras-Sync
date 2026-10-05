//! `fs.grep` and `fs.find` with ripgrep's crates. pi's grep runs ripgrep on the
//! portal and cannot be delegated, so the device searches itself.
//!
//! Walks honour `.gitignore`, include hidden files, never enter `.git` and never
//! follow symlinks. Every file is opened through the same checked open as `fs.read`,
//! and the `allowed` filter (protected paths) is asked for every entry.

use std::io::Read;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobMatcher};
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch};
use sync_policy::Permit;
use sync_policy::paths::to_wire;
use sync_proto::methods::{FindResult, GrepLine, GrepResult};
use sync_proto::{RpcError, code};

use crate::fsops::{MAX_READ, OpenMode, io_error, open_checked};

pub const GREP_DEFAULT_LIMIT: u32 = 100;
pub const FIND_DEFAULT_LIMIT: u32 = 1000;
pub const MAX_LIMIT: u32 = 10_000;
/// Longest line text returned; longer lines are cut.
const MAX_LINE: usize = 2000;

pub struct GrepOptions<'a> {
    pub pattern: &'a str,
    pub glob: Option<&'a str>,
    pub ignore_case: bool,
    pub literal: bool,
    pub context: u32,
    pub limit: Option<u32>,
}

/// A glob without `/` matches the file name anywhere (`*.rs`); with `/` it matches
/// the path relative to the search root (`src/**/*.rs`), like ripgrep's `-g`.
struct NameOrPath {
    m: GlobMatcher,
    full: bool,
}

impl NameOrPath {
    fn new(glob: &str) -> Result<NameOrPath, RpcError> {
        let full = glob.contains('/');
        let g = Glob::new(glob.trim_start_matches('/'))
            .map_err(|e| RpcError::new(code::INVALID_PARAMS, format!("bad glob: {e}")))?;
        Ok(NameOrPath {
            m: g.compile_matcher(),
            full,
        })
    }

    fn is_match(&self, rel: &Path) -> bool {
        if self.full {
            self.m.is_match(rel)
        } else {
            rel.file_name().is_some_and(|n| self.m.is_match(n))
        }
    }
}

fn walker(root: &Path) -> ignore::Walk {
    ignore::WalkBuilder::new(root)
        .hidden(false)
        .follow_links(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .require_git(false)
        .parents(true)
        .filter_entry(|e| e.file_name() != ".git")
        .build()
}

fn sub_permit(base: &Permit, path: PathBuf) -> Permit {
    Permit {
        path,
        root: base.root.clone(),
        confine: base.confine.clone(),
        elevate: None,
    }
}

struct Collect<'a> {
    path: String,
    out: &'a mut Vec<GrepLine>,
    matches: &'a mut u32,
    limit: u32,
}

fn clip_line(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let s = s.trim_end_matches(['\n', '\r']);
    if s.len() > MAX_LINE {
        let mut end = MAX_LINE;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    } else {
        s.to_string()
    }
}

impl Sink for Collect<'_> {
    type Error = std::io::Error;

    fn matched(&mut self, _s: &Searcher, m: &SinkMatch<'_>) -> Result<bool, Self::Error> {
        if *self.matches >= self.limit {
            return Ok(false);
        }
        *self.matches += 1;
        self.out.push(GrepLine {
            path: self.path.clone(),
            line: m.line_number().unwrap_or(0),
            text: clip_line(m.bytes()),
            context: false,
        });
        Ok(*self.matches < self.limit)
    }

    fn context(&mut self, _s: &Searcher, c: &SinkContext<'_>) -> Result<bool, Self::Error> {
        self.out.push(GrepLine {
            path: self.path.clone(),
            line: c.line_number().unwrap_or(0),
            text: clip_line(c.bytes()),
            context: true,
        });
        Ok(true)
    }
}

/// Searches `permit.path` (a file or a directory). `allowed` says whether a walked
/// path may be read (protected paths are skipped, not prompted for one by one).
pub fn grep(
    permit: &Permit,
    opts: &GrepOptions<'_>,
    allowed: &dyn Fn(&Path) -> bool,
) -> Result<GrepResult, RpcError> {
    let limit = opts.limit.unwrap_or(GREP_DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(opts.ignore_case)
        .fixed_strings(opts.literal)
        .build(opts.pattern)
        .map_err(|e| RpcError::new(code::INVALID_PARAMS, format!("bad pattern: {e}")))?;
    let glob = opts.glob.map(NameOrPath::new).transpose()?;
    let ctx = opts.context.min(20) as usize;
    let mut searcher = SearcherBuilder::new()
        .line_number(true)
        .before_context(ctx)
        .after_context(ctx)
        .binary_detection(BinaryDetection::quit(0))
        .build();
    let mut lines = Vec::new();
    let mut matches = 0u32;
    let mut skipped = 0u32;
    let root = permit.path.clone();
    let is_dir = std::fs::symlink_metadata(&root).map_err(io_error)?.is_dir();
    let files: Box<dyn Iterator<Item = PathBuf>> = if is_dir {
        Box::new(walker(&root).filter_map(|e| e.ok()).filter_map(|e| {
            e.file_type()
                .is_some_and(|t| t.is_file())
                .then(|| e.into_path())
        }))
    } else {
        Box::new(std::iter::once(root.clone()))
    };
    for path in files {
        if matches >= limit {
            break;
        }
        if let Some(g) = &glob
            && is_dir
            && !g.is_match(path.strip_prefix(&root).unwrap_or(&path))
        {
            continue;
        }
        if !allowed(&path) {
            skipped += 1;
            continue;
        }
        let Ok(f) = open_checked(&sub_permit(permit, path.clone()), OpenMode::Read) else {
            skipped += 1;
            continue;
        };
        if f.metadata()
            .map(|m| !m.is_file() || m.len() > MAX_READ)
            .unwrap_or(true)
        {
            skipped += 1;
            continue;
        }
        let mut sink = Collect {
            path: to_wire(&path),
            out: &mut lines,
            matches: &mut matches,
            limit,
        };
        if searcher
            .search_reader(&matcher, f.take(MAX_READ), &mut sink)
            .is_err()
        {
            skipped += 1;
        }
    }
    Ok(GrepResult {
        truncated: matches >= limit,
        lines,
        skipped,
    })
}

/// Finds entries under `permit.path` whose name (or relative path) matches `pattern`.
/// Directories end in `/`.
pub fn find(
    permit: &Permit,
    pattern: &str,
    limit: Option<u32>,
    allowed: &dyn Fn(&Path) -> bool,
) -> Result<FindResult, RpcError> {
    let limit = limit.unwrap_or(FIND_DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
    let glob = NameOrPath::new(pattern)?;
    let root = &permit.path;
    if !std::fs::symlink_metadata(root).map_err(io_error)?.is_dir() {
        return Err(RpcError::new(code::IO, "not a directory"));
    }
    let mut paths = Vec::new();
    let mut skipped = 0u32;
    let mut truncated = false;
    for e in walker(root).filter_map(|e| e.ok()) {
        if e.depth() == 0 {
            continue;
        }
        let rel = e.path().strip_prefix(root).unwrap_or(e.path());
        if !glob.is_match(rel) {
            continue;
        }
        if !allowed(e.path()) {
            skipped += 1;
            continue;
        }
        if paths.len() >= limit {
            truncated = true;
            break;
        }
        let mut s = to_wire(e.path());
        if e.file_type().is_some_and(|t| t.is_dir()) {
            s.push('/');
        }
        paths.push(s);
    }
    paths.sort();
    Ok(FindResult {
        paths,
        truncated,
        skipped,
    })
}
