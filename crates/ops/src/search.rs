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

/// Longest pattern `fs.grep` takes.
pub const MAX_PATTERN: usize = 4096;
/// Size limits of a compiled pattern and of its lazy DFA's cache. grep-regex's
/// defaults (100 MiB and 1000 MiB) suit a local user; the portal's pattern gets a
/// few MiB, ample for ordinary searches (`\w{2000}` alone would take 250 MB).
const REGEX_SIZE_LIMIT: usize = 8 << 20;
const REGEX_DFA_LIMIT: usize = 8 << 20;
/// Searches (grep and find) running at once in this process; more wait. Most of a
/// search's memory is its matcher and the walk, which no answer budget bounds.
pub const MAX_SEARCHES: usize = 4;

static SEARCHES: (std::sync::Mutex<usize>, std::sync::Condvar) =
    (std::sync::Mutex::new(0), std::sync::Condvar::new());

/// One of the `MAX_SEARCHES` places, held for a search's whole run.
pub struct SearchSlot(());

/// Waits for a free search place (blocking: searches run on blocking threads).
pub fn search_slot() -> SearchSlot {
    let (n, freed) = &SEARCHES;
    let mut n = n.lock().unwrap_or_else(|e| e.into_inner());
    while *n >= MAX_SEARCHES {
        n = freed.wait(n).unwrap_or_else(|e| e.into_inner());
    }
    *n += 1;
    SearchSlot(())
}

impl Drop for SearchSlot {
    fn drop(&mut self) {
        let (n, freed) = &SEARCHES;
        *n.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        freed.notify_one();
    }
}

pub const GREP_DEFAULT_LIMIT: u32 = 100;
pub const FIND_DEFAULT_LIMIT: u32 = 1000;
pub const MAX_LIMIT: u32 = 10_000;
/// Longest line text returned; longer lines are cut.
const MAX_LINE: usize = 2000;
/// Most bytes of JSON one answer of `fs.grep`, `fs.find` or `fs.list` holds, well
/// below the protocol's 4 MiB message limit: past it the answer stops and says
/// `truncated`. Context lines count too.
pub const MAX_ANSWER: usize = 3 << 20;
/// What one entry adds to an answer besides its strings (field names, numbers).
const ENTRY_OVERHEAD: usize = 64;

/// The length of `s` as a JSON string, escapes included.
pub fn json_len(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum::<usize>()
}

/// Counts the bytes of an answer as entries are added.
pub struct Budget {
    used: usize,
    max: usize,
}

impl Budget {
    pub fn new(max: usize) -> Budget {
        Budget { used: 0, max }
    }

    /// Takes room for an entry with these strings; false (and nothing taken) when
    /// the answer is full.
    pub fn take(&mut self, strings: &[&str]) -> bool {
        let n = ENTRY_OVERHEAD + strings.iter().map(|s| json_len(s)).sum::<usize>();
        if self.used + n > self.max {
            return false;
        }
        self.used += n;
        true
    }
}

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
        if glob.len() > MAX_PATTERN {
            return Err(RpcError::new(
                code::INVALID_PARAMS,
                format!("a glob has at most {MAX_PATTERN} bytes"),
            ));
        }
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
    budget: &'a mut Budget,
    full: &'a mut bool,
}

impl Collect<'_> {
    /// Adds a line if the answer has room for it; false stops the search.
    fn push(&mut self, line: u64, text: String, context: bool) -> bool {
        if !self.budget.take(&[&self.path, &text]) {
            *self.full = true;
            return false;
        }
        self.out.push(GrepLine {
            path: self.path.clone(),
            line,
            text,
            context,
        });
        true
    }
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
        if !self.push(m.line_number().unwrap_or(0), clip_line(m.bytes()), false) {
            return Ok(false);
        }
        *self.matches += 1;
        Ok(*self.matches < self.limit)
    }

    fn context(&mut self, _s: &Searcher, c: &SinkContext<'_>) -> Result<bool, Self::Error> {
        Ok(self.push(c.line_number().unwrap_or(0), clip_line(c.bytes()), true))
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
    if opts.pattern.len() > MAX_PATTERN {
        return Err(RpcError::new(
            code::INVALID_PARAMS,
            format!("a pattern has at most {MAX_PATTERN} bytes"),
        ));
    }
    let _slot = search_slot();
    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(opts.ignore_case)
        .fixed_strings(opts.literal)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_LIMIT)
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
    let mut budget = Budget::new(MAX_ANSWER);
    let mut full = false;
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
        if matches >= limit || full {
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
            budget: &mut budget,
            full: &mut full,
        };
        if searcher
            .search_reader(&matcher, f.take(MAX_READ), &mut sink)
            .is_err()
        {
            skipped += 1;
        }
    }
    Ok(GrepResult {
        truncated: matches >= limit || full,
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
    let _slot = search_slot();
    let root = &permit.path;
    if !std::fs::symlink_metadata(root).map_err(io_error)?.is_dir() {
        return Err(RpcError::new(code::IO, "not a directory"));
    }
    let mut paths = Vec::new();
    let mut skipped = 0u32;
    let mut truncated = false;
    let mut budget = Budget::new(MAX_ANSWER);
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
        if !budget.take(&[&s]) {
            truncated = true;
            break;
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
