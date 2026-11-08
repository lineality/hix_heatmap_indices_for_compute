//! # hix_heatmap_indices_for_compute.rs: count-heat analysis
//!
//! ## Purpose
//! HIX maps where a Rust program spends its executions, to find the "low
//! staves" of the Liebig barrel: the few functions and loops that dominate
//! the work. This module measures count-heat: exact execution counts per
//! function and per loop, from one instrumented run of the target program.
//!
//! ## Use-type and priorities
//! - Local developer analysis tool, run on demand, one-shot CLI.
//! - Transparent, deterministic, reproducible numbers: every figure in the
//!   report can be traced to its method in the `[provenance]` block.
//! - Analysis that scales with sanity: no AST and no type analysis; files
//!   whose every line count is 0 are skipped without being opened.
//! - std only (no crates), so this single module is portable.
//!
//! ## Pipeline
//! 1. Read an LCOV file produced by `cargo llvm-cov report --lcov` from a run
//!    of the target program built with `-C instrument-coverage`.
//! 2. FUNCTION sites: from `FN:`/`FNDA:` records. Function entry counts are
//!    exact (LLVM counters, not samples). Monomorphized instances that share
//!    one source line are summed into one site, and the number of merged
//!    instances is reported.
//! 3. LOOP sites: a lexical line scan of each non-cold source file finds loop
//!    headers (`for`, `while`, `loop`, optionally labeled). The loop's count is
//!    the LCOV `DA:` execution count of the header line, which approximates
//!    the iteration count. Each loop is attributed to the nearest preceding
//!    function definition line in that file.
//! 4. Rank (hottest first, deterministic tie-break by file then line), then
//!    summarize: totals, zero-count sites, concentration (how many sites carry
//!    50% / 90% / 99% of counts), cold tail, order-of-magnitude histogram,
//!    distribution shape, and co-count groups.
//! 5. Write a text report (file + stdout) and a TSV with every site. Site
//!    identity in the TSV is `source_path` + `line`, so other per-site data
//!    (for example sampled time) can be joined onto it.
//!
//! ## Output-directory safety
//! HIX never overwrites earlier results. `--out-dir` must name a path that
//! does not exist yet; its parent (e.g. the `run_NNN_<scenario>` folder) is
//! created if missing.
//! 1. Before any analysis: any existing entry at `--out-dir` (directory,
//!    file, or symlink) stops the run with code 510. Nothing is read or
//!    written, so a name collision costs no analysis time.
//! 2. At write time the directory is created atomically (`create_dir`, which
//!    fails if the path exists). If something else created it in the
//!    meantime, the run stops with code 513 instead of mixing outputs.
//! 3. Report files are opened create-new (never truncate): code 515 if one
//!    exists.
//! If a write fails after the directory was created, the partial directory is
//! left in place (HIX never deletes); rerun with a new analysis name.
//!
//! ## Run metadata
//! Optional flags describe the run that produced the LCOV, so reports from
//! different runs can be compared fairly:
//! - `--run-label` (e.g. `run_005_pumpkin_world_spawn_only`)
//! - `--run-duration-secs` (how long the instrumented program ran)
//! - `--work-units` + `--work-unit-name` (work done, e.g. `1200 chunks_generated`;
//!   always given together)
//! All are printed in `[provenance]` (`(not given)` when absent). With duration
//! and work units both given, work units per minute is shown. With work units
//! given, the TSV gains an appended column `count_per_work_unit`.
//! Text values: 1..=max bytes of `A-Z a-z 0-9 _ - .` (safe in report, TSV, folder names).
//!
//! ## Known limitations
//! - Loop detection is lexical: loops that do not start a line
//!   (`let x = loop {`, `} else { for ...`) are missed; a line inside a
//!   multi-line string that starts with `for ` may be a false positive (it
//!   usually has no line count and is then reported as "no line count").
//!   Block comments are tracked only when `/*` starts a line.
//! - Iterator-adaptor loops (`.for_each(...)`, `.map(...)`) are not loop sites,
//!   but their closures appear as function sites (LLVM instruments closures).
//! - Loop attribution uses the nearest preceding function definition (there
//!   are no function end-lines without an AST). A loop placed after a nested
//!   fn or closure may be attributed to that inner fn; a counted loop whose
//!   attributed fn has count 0 is flagged "attribution suspect".
//! - Stop condition: counts cover the whole run, until the instrumented
//!   program exited cleanly. There is no in-tool duration or count cap.
//! - Function names may be mangled depending on tool versions; identity is
//!   `source_path:line`, so counts are unaffected.
//! - TSV fields are not escaped (paths containing tabs would break columns).
//! - Over-long source lines: a source line longer than `MAX_LINE_BYTES`
//!   (64 KiB) does not cause the file to be skipped. The first 64 KiB of the
//!   line are scanned exactly like a normal line (a loop keyword or comment
//!   marker at the start of the line is still found). The rest of the line is
//!   read and discarded; while discarding, the scanner checks only for a
//!   block-comment end `*/`, so comment tracking stays correct. The file is
//!   skipped only if the discarded remainder of one line exceeds
//!   `MAX_SKIPPED_LINE_BYTES` (64 MiB). Over-long LCOV lines are a fatal
//!   error, because a real LCOV line is always short.
//! - Block-comment tracking uses "does this line contain `*/`": a line that
//!   closes one block comment and opens another (`*/ ... /*`) is treated as
//!   closed. This applies to normal and over-long lines alike.
//! - Nested block comments (`/* /* */ */`) are closed at the first `*/`.
//!   Loop keywords in the rest of such a comment usually have no line count
//!   and are then reported as "no line count".
//! - Distribution-shape figures are descriptive (marked experimental in the
//!   report): they summarize how counts are spread, for comparing runs; they
//!   do not by themselves indicate a problem.
//!
//! ## Modes
//! - Production-release: never panics; errors are 2-byte `HeatmapError` codes;
//!   no printing of errors inside functions (only the top level reports a code).
//! - Debug: verbose `eprintln!` diagnostics (gated `#[cfg(debug_assertions)]`);
//!   internal-invariant `debug_assert!` gated
//!   `#[cfg(all(debug_assertions, not(test)))]`.
//! - Test: `#[cfg(test)]` unit tests using `assert!`/`unwrap`.
//!
//! ## Recovery tiers
//! - Tier 1: transient file-open errors retried with bounded backoff.
//! - Tier 2: a source file that cannot be scanned is skipped, counted, and
//!   listed in the report; the analysis continues.
//! - Tier 3: top-level (`main`) logs the numeric code and exits non-zero.
//!
//! ## Heap policy
//! Heap is used for analysis data (unavoidable for variable-size input),
//! capped by the `MAX_*` constants. The error path never allocates.
//!
//! ## Config files
//! A config file (`config_files/hix_<scenario>.toml`, kept next to
//! `modeling_data/`) holds what is needed to repeat a run: the target crate
//! and binary, the `modeling_data` folder, the scenario name, and analysis
//! options. It is written create-new (never overwritten), then read back and
//! compared before it is used. It is read with the no-heap field-reader
//! described below. Keys and reading rules: see the "HIX config files" section.
//!
//! # Config File TOML Reading:
//! ### From: read_toml_single_line_field_no_heap.rs
//! Functionality: Read Single Line Field = RSLF
//!
//! ## Error/Mode Policy:
//! https://github.com/lineality/rust_lang_rules
//! https://github.com/lineality/modes_and_case_handling
//! https://github.com/lineality/modes_and_case_handling/blob/main/mode_case_handling_framework_summary.md
//!
//! Source: https://github.com/lineality/toml_read_field_noheap_rust
//!
//! ## Purpose
//! Reads one short value for one top-level key from a small configuration
//! file written in a TOML subset, without heap allocation. Optionally checks
//! that given keys appear at most once in the file.
//!
//! ## Public functions
//! - `read_single_line_field_from_toml_no_heap::<N>(path, key)`:
//!   returns the value of the first line that assigns `key`, in an `N`-byte
//!   stack array, plus the number of meaningful bytes.
//! - `count_toml_key_lines_no_heap(path, key)`: number of lines that assign `key`.
//! - `check_toml_keys_are_unique_no_heap(path, keys)`: error 816 if any key in
//!   `keys` is assigned on more than one line.
//!
//! ## Why no heap, and why one byte at a time
//! The usual idiom `BufReader::new(File).lines()` heap-allocates a ~8 KiB
//! read buffer and one `String` per line, and hands owned `String`s to the
//! caller. To read one short value, this module instead:
//! - reads the file one byte per read call (no read-chunk buffer, no line buffer);
//! - compares key bytes in place against the caller's key (the key is never copied);
//! - writes only the matched value's bytes, directly into the caller's
//!   fixed-size output array.
//!
//! Bounding the output to the size the task needs is also input sanitation:
//! a value longer than the buffer cannot enter. It is refused with code 812,
//! never silently truncated.
//!
//! Cost: one read call per byte, and one file open per call. For the intended
//! use (a config file of a few dozen short lines, read a few times at startup)
//! this is negligible.
//!
//! ## Accepted file format (TOML subset)
//! - One `key = value` per line, top level only (no `[section]` support).
//! - Leading spaces and tabs are allowed, and so are spaces and tabs around `=`.
//! - Lines whose first non-whitespace byte is `#` are comments.
//! - LF or CRLF line endings.
//! - Values: double-quoted (`"..."`), or unquoted (numbers, bare words).
//! - Keys are matched exactly, byte for byte (case-sensitive). A longer key
//!   that starts with the requested key (`name_long` vs `name`) does not match.
//!
//! ## Value termination policy
//! - Quoted values end at the next `"`. End of file before it: code 813.
//! - Unquoted values end at the next `\n`; a `\r` directly before it is not
//!   part of the value. End of file before `\n`: code 813. Spaces or tabs
//!   before the `\n` ARE part of the value (the caller trims if wanted).
//! - `key =` followed directly by `\n`: an empty value (length 0), not an error.
//!
//! ## Not supported (non-goals)
//! - Full TOML: arrays, tables, inline tables, multi-line strings, escape
//!   sequences (a `\` is copied as a plain byte), dotted keys, datetimes.
//! - Trailing comments after an unquoted value: `port = 80 # x` yields the
//!   value `80 # x`. After a quoted value they are ignored.
//! - A UTF-8 byte-order mark at file start (the first key would not match).
//! - Converting the value to text: the caller decides (e.g. `str::from_utf8`).
//!
//! A quoted value that contains a newline is read across the newline (it
//! ends at `"`). Key-line counting does not know about such values, so a
//! line inside one could be counted as a key line. Files written by a
//! writer that refuses newlines in values never contain this case.
//!
//! ## Architecture
//! `scan_toml_reader_for_key` drives a finite-state machine (`LineScanState`)
//! one byte per read call, through `apply_byte_to_scan`. The scan has one of
//! two goals (`ScanGoal`): copy the first matching value, or count key lines.
//! The scanner works on any `Read`; the public functions give it an
//! unbuffered `File`, and tests give it in-memory input.
//!
//! ## RSLF Error codes
//! Codes 801-816 are used; 817-849 are reserved for the matching config
//! writer. Numbers range from 800-849 so that they may often be kept
//! unchanged when this module is merged into a parent project in development.
//! The table is in the `HeatmapError` doc comment.
//!
//! ## Modes
//! - Production-release: never panics, never allocates; errors are 2-byte codes;
//!   no printing.
//! - Debug: gated `eprintln!` diagnostics (may print the path and key);
//!   internal invariants (801, 802, 814, 815) also `debug_assert!`, gated
//!   `#[cfg(all(debug_assertions, not(test)))]`.
//! - Test: `#[cfg(test)]` unit tests using `assert!`/`unwrap`.
//!
//! ## Recovery tiers
//! - Tier 1: transient open errors are retried with bounded backoff;
//!   interrupted reads are retried within a bounded read-call allowance.
//! - Tiers 2 and 3 belong to the caller (e.g. use a default, or stop with the code).
//!
//! ## Concurrency
//! Synchronous, no shared state. Safe to call from several threads.
//!
//! #### Rust Policy, See:
//! https://github.com/lineality/rust_lang_rules
//! https://github.com/lineality/modes_and_case_handling
//! https://github.com/lineality/modes_and_case_handling/blob/main/mode_case_handling_framework_summary.md

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
// ============================================================================
// Constants (all loops and buffers are bounded by these)
// ============================================================================

/// Maximum number of `--flag value` pairs accepted on the command line.
/// Equals the number of distinct flags (`--lcov`, `--out-dir`, `--top-n`,
/// `--run-label`, `--run-duration-secs`, `--work-units`, `--work-unit-name`)
/// and the number of fields in `RawCliFlagValues`.
/// Each flag may appear at most once, so any further argument is
/// "too many arguments" (code 101). Raise this when a flag is added;
/// the test `cli_parse_cli_arguments_extra_pair_with_code_101` fails if not.
const MAX_CLI_FLAG_PAIRS: usize = 7;

/// Longest accepted `--run-label` (bytes; ASCII only, so also characters).
const MAX_RUN_LABEL_BYTES: usize = 128;

/// Longest accepted `--work-unit-name` (bytes; ASCII only, so also characters).
const MAX_WORK_UNIT_NAME_BYTES: usize = 64;

/// Longest accepted `--run-duration-secs`: 365 days. Far above any real run;
/// a larger value is almost certainly a typo (e.g. milliseconds given).
const MAX_RUN_DURATION_SECS: u64 = 31_536_000;

/// Largest accepted `--work-units` (10^15): a sanity bound, not a real limit.
const MAX_WORK_UNITS: u64 = 1_000_000_000_000_000;

/// Default number of rows in each Top-N table when `--top-n` is not given.
const DEFAULT_TOP_N: u16 = 20;

/// Upper bound for `--top-n` (keeps the text report human-sized).
const MAX_TOP_N: u16 = 10_000;

/// Maximum bytes kept for one line of text (the newline byte counts too).
///
/// - LCOV input: a longer line is a fatal error (`LcovLineTooLong`), because
///   every real LCOV record line is short; a longer one means corrupt input.
/// - Source files (loop scan): a longer line is NOT an error.
///   Its first `MAX_LINE_BYTES + 1` bytes are kept and scanned normally (loop
///   keywords and comment markers sit at the start of a line), and the rest
///   of the line is read and discarded. See `read_source_line_skipping_overlong`.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Source scan only: the longest remainder of one over-long line that the
/// scanner will read and discard before giving up on that file.
///
/// Why a cap exists: discarding is a loop, and every loop in this tool is
/// bounded. 64 MiB is far above any line expected even in generated source
/// files. If one line's remainder exceeds it, the file is skipped (Tier 2)
/// and counted under "files skipped: line > MAX_SKIPPED_LINE_BYTES".
const MAX_SKIPPED_LINE_BYTES: usize = 64 * 1024 * 1024;

/// Source scan only: extra read calls allowed while discarding, on top of
/// one call per discarded byte.
///
/// Every successful read call discards at least one byte, so the byte cap
/// already bounds them. Only "interrupted" reads (the operating system asks
/// the program to try again; nothing is read) use these extra calls. This
/// keeps the discard loop finite even if a reader reports "interrupted" forever.
const SKIP_LINE_EXTRA_READ_CALLS: usize = 1024;

/// Maximum number of lines read from one LCOV file.
const MAX_LCOV_LINES: usize = 50_000_000;

/// Maximum number of `FN`/`FNDA`/`DA` entries accepted from one LCOV file.
const MAX_COVERAGE_ENTRIES: usize = 20_000_000;

/// Maximum number of source-file records (`SF:`) accepted from one LCOV file.
const MAX_SOURCE_FILES: usize = 200_000;

/// Maximum number of lines scanned in one source file.
const MAX_SOURCE_LINES_PER_FILE: usize = 1_000_000;

/// Tier-1 retry: maximum attempts to open a file on transient errors.
const MAX_OPEN_ATTEMPTS: u32 = 3;

/// Tier-1 retry: backoff step in milliseconds (attempt n sleeps n * step).
const OPEN_RETRY_BACKOFF_STEP_MS: u64 = 50;

/// Number of concentration targets: the only place this count is written.
const CONCENTRATION_TARGET_COUNT: usize = 3;

/// Concentration targets: "the hottest K sites carry P% of all counts".
/// Ascending. The last target also defines the cold tail
/// ("the remaining sites carry <= 100 - P% of counts").
const CONCENTRATION_TARGETS_PERCENT: [u128; CONCENTRATION_TARGET_COUNT] = [50, 90, 99];

/// Distribution shape: "share of all counts carried by the hottest K sites",
/// reported for these two K values (narrow and wide view of the head).
const TOP_SHARE_NARROW_SITES: usize = 1;
const TOP_SHARE_WIDE_SITES: usize = 10;

/// Order-of-magnitude histogram buckets: bucket 0 = count 0,
/// bucket d (1..=20) = count in [10^(d-1), 10^d). u64::MAX has 20 digits.
const DECADE_BUCKET_COUNT: usize = 21;

/// Initial capacity for in-memory report buffers.
const REPORT_BUFFER_INITIAL_CAPACITY: usize = 64 * 1024;

/// Output file name for the human-readable report (inside `--out-dir`).
const REPORT_FILE_NAME: &str = "hix_report.txt";

/// Output file name for the full per-site TSV data (inside `--out-dir`).
const SITES_TSV_FILE_NAME: &str = "hix_sites.tsv";

/// Error log file name, created next to the executable (codes only, no PII).
const ERROR_LOG_FILE_NAME: &str = "hix_error_log.txt";

/// Usage text shown by `main` for command-line errors (static: no heap).
pub const USAGE_TEXT: &str = "\
usage: hix --lcov /ABSOLUTE/path/file.lcov --out-dir /ABSOLUTE/output/dir [--top-n 1..10000]
           [--run-label LABEL] [--run-duration-secs N] [--work-units N --work-unit-name NAME]

  --lcov               LCOV file from: cargo llvm-cov report --lcov --output-path /ABSOLUTE/file.lcov
  --out-dir            NEW directory for hix_report.txt and hix_sites.tsv; must not exist yet
                       (HIX never overwrites; the parent directory is created if missing)
                       e.g. /ABSOLUTE/modeling_data/run_005_<scenario>/analysis_001_<purpose>
  --top-n              rows per Top-N table (default 20)
  --run-label          optional; e.g. run_005_pumpkin_world_spawn_only
  --run-duration-secs  optional; seconds the instrumented program ran (1..31536000)
  --work-units         optional; work done in the run (1..1000000000000000); needs --work-unit-name
  --work-unit-name     optional; e.g. chunks_generated; needs --work-units
Labels and unit names: 1-128 characters (unit name: 1-64) from A-Z a-z 0-9 _ - .
All paths must be absolute.";

/// Minimum count for a site to take part in co-count groups. Identical counts
/// below this are too likely to be coincidence to indicate structural coupling.
const CO_COUNT_MIN_COUNT: u64 = 100_000;

// ============================================================================
// Error codes
// ============================================================================

/// Project-wide fieldless error code (2 bytes, `Copy`, no heap, no PII).
///
/// Codes are append-only: never renumber or reuse.
///
/// | Block   | Area                                            |
/// |---------|-------------------------------------------------|
/// | 100–149 | command-line arguments                          |
/// | 150–199 | enforced custom types (value integrity)         |
/// | 200–299 | LCOV input file                                 |
/// | 300–399 | source-file loop scan (absorbed at Tier 2)      |
/// | 400–499 | analysis / aggregation                          |
/// | 500–599 | report output                                   |
/// | 600–699 | error log                                       |
/// | 700–799 |                                                 |
/// | 800–849 | config files (read; 817–849 reserved for write) |
// `Debug` (variant names as text) exists only in test and debug builds, so a
// production-release binary contains no variant-name strings, and any stray
// `{:?}` on a HeatmapError in production-release code fails to compile.
// This is an intended guard (see the Modes & Case Handling framework).
#[cfg_attr(any(test, debug_assertions), derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HeatmapError {
    // 100–149: command line
    CliTooManyArguments = 101,
    CliUnknownFlag = 102,
    CliMissingFlagValue = 103,
    CliMissingLcovPath = 104,
    CliMissingOutputDirectory = 105,
    CliTopNNotUtf8 = 106,
    CliTopNNotANumber = 107,
    CliDuplicateFlag = 108,
    CliRunLabelNotUtf8 = 109,
    CliRunDurationNotUtf8 = 110,
    CliRunDurationNotANumber = 111,
    CliWorkUnitsNotUtf8 = 112,
    CliWorkUnitsNotANumber = 113,
    CliWorkUnitNameNotUtf8 = 114,
    CliWorkUnitsWithoutName = 115,
    CliWorkUnitNameWithoutUnits = 116,

    // 150–199: enforced custom types
    TypeTopNOutOfRange = 150,
    TypeTopNCorrupted = 151,
    TypeLineNumberZero = 152,
    TypeLineNumberCorrupted = 153,
    TypePathNotAbsolute = 154,
    TypePathCorrupted = 155,
    TypeRunLabelInvalid = 156,
    TypeRunLabelCorrupted = 157,
    TypeRunDurationOutOfRange = 158,
    TypeRunDurationCorrupted = 159,
    TypeWorkUnitsOutOfRange = 160,
    TypeWorkUnitsCorrupted = 161,
    TypeWorkUnitNameInvalid = 162,
    TypeWorkUnitNameCorrupted = 163,
    TypeScenarioNameInvalid = 164,
    TypeScenarioNameCorrupted = 165,
    TypeCargoBinaryNameInvalid = 166,
    TypeCargoBinaryNameCorrupted = 167,
    TypeAnalysisPurposeInvalid = 168,
    TypeAnalysisPurposeCorrupted = 169,

    // 200–299: LCOV input
    LcovOpenNotFound = 201,
    LcovOpenPermissionDenied = 202,
    LcovOpenTransient = 203,
    LcovOpenOther = 204,
    LcovReadFailed = 205,
    LcovLineTooLong = 206,
    LcovTooManyLines = 207,
    LcovNotUtf8 = 208,
    LcovRecordOutsideFile = 209,
    LcovBadLineNumber = 210,
    LcovBadCount = 211,
    LcovMalformedRecord = 212,
    LcovTooManyEntries = 213,
    LcovUnterminatedRecord = 214,
    LcovNoData = 215,
    LcovCountOverflow = 216,
    LcovTooManyFiles = 217,

    // 300–399: source scan (Tier 2: absorbed per file, counted in report)
    SrcOpenNotFound = 301,
    SrcOpenPermissionDenied = 302,
    SrcOpenTransient = 303,
    SrcOpenOther = 304,
    SrcReadFailed = 305,
    SrcTooManyLines = 306,
    SrcLineNumberOverflow = 307,
    SrcLineExceedsSkipCap = 308,
    SrcSkipReadFailed = 309,
    SrcSkipReadCallLimit = 310,

    // 400–499: analysis
    AnaCountOverflow = 401,
    AnaFileIndexInvalid = 402,
    AnaSiteIndexInvalid = 403,
    AnaHistogramIndexInvalid = 404,
    AnaFunctionLineIndexOverflow = 405,
    AnaCoCountRunInvalid = 406,
    AnaLoopScanTotalsMismatch = 407,
    AnaLoopScanFileNotesMismatch = 408,
    AnaShapeInputNotSorted = 409,
    AnaShapeSumOverflow = 410,
    AnaShapeDropIndexInvalid = 411,

    // 500–599: report output
    RptCreateDirectoryFailed = 501,
    RptOpenNotFound = 502,
    RptOpenPermissionDenied = 503,
    RptOpenTransient = 504,
    RptOpenOther = 505,
    RptBufferWriteFailed = 506,
    RptFileWriteFailed = 507,
    RptFlushFailed = 508,
    RptStdoutWriteFailed = 509,
    RptOutputPathAlreadyExists = 510,
    RptOutputPathCheckFailed = 511,
    RptOutputPathHasNoParent = 512,
    RptOutputDirectoryAppearedDuringRun = 513,
    RptOutputParentCreateFailed = 514,
    RptOpenAlreadyExists = 515,

    // 600–699: error log
    LogExecutablePathUnavailable = 601,
    LogExecutableParentMissing = 602,
    LogOpenFailed = 603,
    LogWriteFailed = 604,
    LogClockBeforeEpoch = 605,

    // 700–799: ...

    // 800-849: TOML/Config file read/write
    // 800-816: for toml/config writer reader
    // Functionality: Read Single Line Field = RSLF
    RSLFEmptyKey = 801,
    RSLFOutputBufferZeroSized = 802,
    RSLFPathNotAbsolute = 803,
    RSLFOpenNotFound = 804,
    RSLFOpenPermissionDenied = 805,
    RSLFOpenTransient = 806,
    RSLFOpenOther = 807,
    RSLFReadFailed = 808,
    RSLFReadCallLimitReached = 809,
    RSLFFileExceedsScanLimit = 810,
    RSLFFieldNotFound = 811,
    RSLFValueExceedsOutputBuffer = 812,
    RSLFValueUnterminatedAtEndOfFile = 813,
    RSLFKeyMatchIndexInvalid = 814,
    RSLFScanOutcomeMismatch = 815,
    RSLFDuplicateKey = 816,

    // 817–849: HIX config files (values, write, read-back, load)
    CfgPathNotAbsolute = 817,
    CfgPathValueInvalid = 818,
    CfgPathValueCorrupted = 819,
    CfgRenderBufferFull = 820,
    CfgWriteOpenNotFound = 821,
    CfgWriteOpenPermissionDenied = 822,
    CfgWriteOpenTransient = 823,
    CfgWriteOpenAlreadyExists = 824,
    CfgWriteOpenOther = 825,
    CfgWriteFailed = 826,
    CfgSyncFailed = 827,
    CfgRoundTripMismatch = 828,
    CfgValueLengthInvalid = 829,
    CfgValueNotUtf8 = 830,
    CfgVersionNotANumber = 831,
    CfgUnsupportedVersion = 832,
    CfgTopNInvalid = 833,
    CfgBooleanInvalid = 834,
    CfgWorkUnitNameInvalid = 835,
    CfgRenderedRangeInvalid = 836,
}

impl HeatmapError {
    /// Numeric code (stable, append-only). Safe to print or log in any mode.
    pub fn code(self) -> u16 {
        self as u16
    }

    /// Tier-1 policy: may the caller retry the same bounded operation?
    /// Defined per code (exhaustive, no wildcard) so new codes force a decision.
    pub fn is_retryable(self) -> bool {
        match self {
            HeatmapError::RSLFOpenTransient
            | HeatmapError::LcovOpenTransient
            | HeatmapError::SrcOpenTransient
            | HeatmapError::CfgWriteOpenTransient
            | HeatmapError::RptOpenTransient => true,

            HeatmapError::AnaCoCountRunInvalid
            | HeatmapError::AnaShapeInputNotSorted
            | HeatmapError::AnaShapeSumOverflow
            | HeatmapError::AnaShapeDropIndexInvalid
            | HeatmapError::AnaCountOverflow
            | HeatmapError::AnaLoopScanFileNotesMismatch
            | HeatmapError::AnaLoopScanTotalsMismatch
            | HeatmapError::AnaFileIndexInvalid
            | HeatmapError::AnaFunctionLineIndexOverflow
            | HeatmapError::AnaHistogramIndexInvalid
            | HeatmapError::AnaSiteIndexInvalid
            | HeatmapError::CliTooManyArguments
            | HeatmapError::CliUnknownFlag
            | HeatmapError::CliMissingFlagValue
            | HeatmapError::CliMissingLcovPath
            | HeatmapError::CliMissingOutputDirectory
            | HeatmapError::CliTopNNotUtf8
            | HeatmapError::CliTopNNotANumber
            | HeatmapError::CliDuplicateFlag
            | HeatmapError::LcovOpenNotFound
            | HeatmapError::LcovOpenPermissionDenied
            | HeatmapError::LcovOpenOther
            | HeatmapError::LcovReadFailed
            | HeatmapError::LcovLineTooLong
            | HeatmapError::LcovTooManyLines
            | HeatmapError::LcovNotUtf8
            | HeatmapError::LcovRecordOutsideFile
            | HeatmapError::LcovBadLineNumber
            | HeatmapError::LcovBadCount
            | HeatmapError::LcovMalformedRecord
            | HeatmapError::LcovTooManyEntries
            | HeatmapError::LcovUnterminatedRecord
            | HeatmapError::LcovNoData
            | HeatmapError::LcovCountOverflow
            | HeatmapError::LcovTooManyFiles
            | HeatmapError::LogExecutablePathUnavailable
            | HeatmapError::LogExecutableParentMissing
            | HeatmapError::LogOpenFailed
            | HeatmapError::LogWriteFailed
            | HeatmapError::RptCreateDirectoryFailed
            | HeatmapError::RptOpenNotFound
            | HeatmapError::RptOpenPermissionDenied
            | HeatmapError::RptOpenOther
            | HeatmapError::RptBufferWriteFailed
            | HeatmapError::RptFileWriteFailed
            | HeatmapError::RptFlushFailed
            | HeatmapError::RptStdoutWriteFailed
            | HeatmapError::RptOutputPathAlreadyExists
            | HeatmapError::RptOutputPathCheckFailed
            | HeatmapError::RptOutputPathHasNoParent
            | HeatmapError::RptOutputDirectoryAppearedDuringRun
            | HeatmapError::RptOutputParentCreateFailed
            | HeatmapError::RptOpenAlreadyExists
            | HeatmapError::SrcOpenNotFound
            | HeatmapError::SrcOpenPermissionDenied
            | HeatmapError::SrcOpenOther
            | HeatmapError::SrcReadFailed
            | HeatmapError::SrcTooManyLines
            | HeatmapError::SrcLineNumberOverflow
            | HeatmapError::SrcLineExceedsSkipCap
            | HeatmapError::SrcSkipReadFailed
            | HeatmapError::SrcSkipReadCallLimit
            | HeatmapError::TypeTopNOutOfRange
            | HeatmapError::TypeTopNCorrupted
            | HeatmapError::TypeLineNumberZero
            | HeatmapError::TypeLineNumberCorrupted
            | HeatmapError::TypePathNotAbsolute
            | HeatmapError::TypePathCorrupted
            | HeatmapError::CliRunLabelNotUtf8
            | HeatmapError::CliRunDurationNotUtf8
            | HeatmapError::CliRunDurationNotANumber
            | HeatmapError::CliWorkUnitsNotUtf8
            | HeatmapError::CliWorkUnitsNotANumber
            | HeatmapError::CliWorkUnitNameNotUtf8
            | HeatmapError::CliWorkUnitsWithoutName
            | HeatmapError::CliWorkUnitNameWithoutUnits
            | HeatmapError::TypeRunLabelInvalid
            | HeatmapError::TypeRunLabelCorrupted
            | HeatmapError::TypeRunDurationOutOfRange
            | HeatmapError::TypeRunDurationCorrupted
            | HeatmapError::TypeWorkUnitsOutOfRange
            | HeatmapError::TypeWorkUnitsCorrupted
            | HeatmapError::TypeWorkUnitNameInvalid
            | HeatmapError::TypeWorkUnitNameCorrupted
            | HeatmapError::LogClockBeforeEpoch
            | HeatmapError::RSLFEmptyKey
            | HeatmapError::RSLFOutputBufferZeroSized
            | HeatmapError::RSLFPathNotAbsolute
            | HeatmapError::RSLFOpenNotFound
            | HeatmapError::RSLFOpenPermissionDenied
            | HeatmapError::RSLFOpenOther
            | HeatmapError::RSLFReadFailed
            | HeatmapError::RSLFReadCallLimitReached
            | HeatmapError::RSLFFileExceedsScanLimit
            | HeatmapError::RSLFFieldNotFound
            | HeatmapError::RSLFValueExceedsOutputBuffer
            | HeatmapError::RSLFValueUnterminatedAtEndOfFile
            | HeatmapError::RSLFKeyMatchIndexInvalid
            | HeatmapError::RSLFScanOutcomeMismatch
            | HeatmapError::RSLFDuplicateKey
            | HeatmapError::TypeScenarioNameInvalid
            | HeatmapError::TypeScenarioNameCorrupted
            | HeatmapError::TypeCargoBinaryNameInvalid
            | HeatmapError::TypeCargoBinaryNameCorrupted
            | HeatmapError::TypeAnalysisPurposeInvalid
            | HeatmapError::TypeAnalysisPurposeCorrupted
            | HeatmapError::CfgPathNotAbsolute
            | HeatmapError::CfgPathValueInvalid
            | HeatmapError::CfgPathValueCorrupted
            | HeatmapError::CfgRenderBufferFull
            | HeatmapError::CfgWriteOpenNotFound
            | HeatmapError::CfgWriteOpenPermissionDenied
            | HeatmapError::CfgWriteOpenAlreadyExists
            | HeatmapError::CfgWriteOpenOther
            | HeatmapError::CfgWriteFailed
            | HeatmapError::CfgSyncFailed
            | HeatmapError::CfgRoundTripMismatch
            | HeatmapError::CfgValueLengthInvalid
            | HeatmapError::CfgValueNotUtf8
            | HeatmapError::CfgVersionNotANumber
            | HeatmapError::CfgUnsupportedVersion
            | HeatmapError::CfgTopNInvalid
            | HeatmapError::CfgBooleanInvalid
            | HeatmapError::CfgWorkUnitNameInvalid
            | HeatmapError::CfgRenderedRangeInvalid => false,
        }
    }

    /// True for errors the user fixes by changing the command line
    /// (used only to decide whether `main` shows `USAGE_TEXT`).
    pub fn is_cli_usage_error(self) -> bool {
        matches!(
            self,
            HeatmapError::CliTooManyArguments
                | HeatmapError::CliUnknownFlag
                | HeatmapError::CliMissingFlagValue
                | HeatmapError::CliMissingLcovPath
                | HeatmapError::CliMissingOutputDirectory
                | HeatmapError::CliTopNNotUtf8
                | HeatmapError::CliTopNNotANumber
                | HeatmapError::CliDuplicateFlag
                | HeatmapError::RptOutputPathAlreadyExists
                | HeatmapError::TypeTopNOutOfRange
                | HeatmapError::TypePathNotAbsolute
                | HeatmapError::CliRunLabelNotUtf8
                | HeatmapError::CliRunDurationNotUtf8
                | HeatmapError::CliRunDurationNotANumber
                | HeatmapError::CliWorkUnitsNotUtf8
                | HeatmapError::CliWorkUnitsNotANumber
                | HeatmapError::CliWorkUnitNameNotUtf8
                | HeatmapError::CliWorkUnitsWithoutName
                | HeatmapError::CliWorkUnitNameWithoutUnits
                | HeatmapError::TypeRunLabelInvalid
                | HeatmapError::TypeRunDurationOutOfRange
                | HeatmapError::TypeWorkUnitsOutOfRange
                | HeatmapError::TypeWorkUnitNameInvalid
        )
    }
}

/// Human-readable descriptions: compiled only in debug and test builds.
#[cfg(any(debug_assertions, test))]
impl std::fmt::Display for HeatmapError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let description: &str = match self {
            HeatmapError::AnaShapeInputNotSorted => {
                "distribution-shape input is not sorted hottest-first"
            }
            HeatmapError::AnaShapeSumOverflow => "distribution-shape weighted sum overflowed u128",
            HeatmapError::AnaShapeDropIndexInvalid => "distribution-shape drop site index invalid",
            HeatmapError::CliRunLabelNotUtf8 => "--run-label value is not UTF-8",
            HeatmapError::CliRunDurationNotUtf8 => "--run-duration-secs value is not UTF-8",
            HeatmapError::CliRunDurationNotANumber => {
                "--run-duration-secs value is not a u64 number"
            }
            HeatmapError::CliWorkUnitsNotUtf8 => "--work-units value is not UTF-8",
            HeatmapError::CliWorkUnitsNotANumber => "--work-units value is not a u64 number",
            HeatmapError::CliWorkUnitNameNotUtf8 => "--work-unit-name value is not UTF-8",
            HeatmapError::CliWorkUnitsWithoutName => "--work-units requires --work-unit-name",
            HeatmapError::CliWorkUnitNameWithoutUnits => "--work-unit-name requires --work-units",
            HeatmapError::TypeRunLabelInvalid => {
                "run label must be 1..=MAX_RUN_LABEL_BYTES of A-Z a-z 0-9 _ - ."
            }
            HeatmapError::TypeRunLabelCorrupted => "RunLabel failed validity recheck",
            HeatmapError::TypeRunDurationOutOfRange => {
                "run duration outside 1..=MAX_RUN_DURATION_SECS"
            }
            HeatmapError::TypeRunDurationCorrupted => "RunDurationSeconds failed validity recheck",
            HeatmapError::TypeWorkUnitsOutOfRange => "work units outside 1..=MAX_WORK_UNITS",
            HeatmapError::TypeWorkUnitsCorrupted => "WorkUnitCount failed validity recheck",
            HeatmapError::TypeWorkUnitNameInvalid => {
                "work unit name must be 1..=MAX_WORK_UNIT_NAME_BYTES of A-Z a-z 0-9 _ - ."
            }
            HeatmapError::TypeWorkUnitNameCorrupted => "WorkUnitName failed validity recheck",
            HeatmapError::AnaLoopScanFileNotesMismatch => {
                "loop-scan file notes do not match the skip / over-long counters"
            }
            HeatmapError::RptOutputPathAlreadyExists => {
                "--out-dir already exists; choose a new analysis name (nothing was read or written)"
            }
            HeatmapError::RptOutputPathCheckFailed => "could not check whether --out-dir exists",
            HeatmapError::RptOutputPathHasNoParent => "--out-dir has no parent directory",
            HeatmapError::RptOutputDirectoryAppearedDuringRun => {
                "--out-dir was created by something else during this run; nothing written"
            }
            HeatmapError::RptOutputParentCreateFailed => {
                "could not create the parent directory of --out-dir"
            }
            HeatmapError::RptOpenAlreadyExists => {
                "report file already exists; refusing to overwrite"
            }
            HeatmapError::AnaFunctionLineIndexOverflow => {
                "function-line index count sum overflowed"
            }
            HeatmapError::AnaCoCountRunInvalid => "co-count group range invalid",
            HeatmapError::AnaLoopScanTotalsMismatch => {
                "loop-scan file counts do not add up to files listed in lcov"
            }
            HeatmapError::CliTooManyArguments => "too many command-line arguments",
            HeatmapError::CliUnknownFlag => "unknown command-line flag",
            HeatmapError::CliMissingFlagValue => "flag given without a value",
            HeatmapError::CliMissingLcovPath => "--lcov is required",
            HeatmapError::CliMissingOutputDirectory => "--out-dir is required",
            HeatmapError::CliTopNNotUtf8 => "--top-n value is not UTF-8",
            HeatmapError::CliTopNNotANumber => "--top-n value is not a u16 number",
            HeatmapError::CliDuplicateFlag => "a flag was given more than once",
            HeatmapError::TypeTopNOutOfRange => "top-n outside 1..=MAX_TOP_N",
            HeatmapError::TypeTopNCorrupted => "TopNCount failed validity recheck",
            HeatmapError::TypeLineNumberZero => "source line number must be >= 1",
            HeatmapError::TypeLineNumberCorrupted => "SourceLineNumber failed validity recheck",
            HeatmapError::TypePathNotAbsolute => "path must be absolute",
            HeatmapError::TypePathCorrupted => "AbsolutePath failed validity recheck",
            HeatmapError::LcovOpenNotFound => "lcov file not found",
            HeatmapError::LcovOpenPermissionDenied => "lcov file permission denied",
            HeatmapError::LcovOpenTransient => {
                "lcov file open: transient error (retries exhausted)"
            }
            HeatmapError::LcovOpenOther => "lcov file open failed",
            HeatmapError::LcovReadFailed => "lcov read failed",
            HeatmapError::LcovLineTooLong => "lcov line exceeds MAX_LINE_BYTES",
            HeatmapError::LcovTooManyLines => "lcov file exceeds MAX_LCOV_LINES",
            HeatmapError::LcovNotUtf8 => "lcov line is not UTF-8",
            HeatmapError::LcovRecordOutsideFile => "lcov entry outside an SF..end_of_record block",
            HeatmapError::LcovBadLineNumber => "lcov line number invalid",
            HeatmapError::LcovBadCount => "lcov execution count invalid",
            HeatmapError::LcovMalformedRecord => "lcov record malformed",
            HeatmapError::LcovTooManyEntries => "lcov exceeds MAX_COVERAGE_ENTRIES",
            HeatmapError::LcovUnterminatedRecord => "lcov ended inside a record",
            HeatmapError::LcovNoData => "lcov contains no source-file records",
            HeatmapError::LcovCountOverflow => "lcov count sum overflowed u64",
            HeatmapError::LcovTooManyFiles => "lcov exceeds MAX_SOURCE_FILES",
            HeatmapError::SrcOpenNotFound => "source file not found",
            HeatmapError::SrcOpenPermissionDenied => "source file permission denied",
            HeatmapError::SrcOpenTransient => {
                "source file open: transient error (retries exhausted)"
            }
            HeatmapError::SrcOpenOther => "source file open failed",
            HeatmapError::SrcReadFailed => "source file read failed",
            HeatmapError::SrcTooManyLines => "source file exceeds MAX_SOURCE_LINES_PER_FILE",
            HeatmapError::SrcLineNumberOverflow => "source line number overflowed u32",
            HeatmapError::SrcLineExceedsSkipCap => {
                "over-long source line remainder exceeds MAX_SKIPPED_LINE_BYTES; file skipped"
            }
            HeatmapError::SrcSkipReadFailed => {
                "source read failed while discarding the rest of an over-long line"
            }
            HeatmapError::SrcSkipReadCallLimit => {
                "discarding an over-long source line exceeded its read-call limit"
            }
            HeatmapError::AnaCountOverflow => "count total overflowed",
            HeatmapError::AnaFileIndexInvalid => "site refers to a missing file record",
            HeatmapError::AnaSiteIndexInvalid => "site index invalid during merge",
            HeatmapError::AnaHistogramIndexInvalid => "histogram bucket index invalid",
            HeatmapError::RptCreateDirectoryFailed => "could not create output directory",
            HeatmapError::RptOpenNotFound => "report path not found",
            HeatmapError::RptOpenPermissionDenied => "report path permission denied",
            HeatmapError::RptOpenTransient => "report open: transient error (retries exhausted)",
            HeatmapError::RptOpenOther => "report open failed",
            HeatmapError::RptBufferWriteFailed => "writing report into memory buffer failed",
            HeatmapError::RptFileWriteFailed => "writing report file failed",
            HeatmapError::RptFlushFailed => "flushing report file failed",
            HeatmapError::RptStdoutWriteFailed => "writing report to stdout failed",
            HeatmapError::LogExecutablePathUnavailable => "executable path unavailable",
            HeatmapError::LogExecutableParentMissing => "executable has no parent directory",
            HeatmapError::LogOpenFailed => "error log open failed",
            HeatmapError::LogWriteFailed => "error log write failed",
            HeatmapError::LogClockBeforeEpoch => "system clock is before UNIX epoch",
            HeatmapError::RSLFEmptyKey => "key is empty",
            HeatmapError::RSLFOutputBufferZeroSized => "OUTPUT_BUFFER_BYTES is 0",
            HeatmapError::RSLFPathNotAbsolute => "toml path is not absolute",
            HeatmapError::RSLFOpenNotFound => "toml file not found",
            HeatmapError::RSLFOpenPermissionDenied => "toml file permission denied",
            HeatmapError::RSLFOpenTransient => {
                "toml file open: transient error (retries exhausted)"
            }
            HeatmapError::RSLFOpenOther => "toml file open failed",
            HeatmapError::RSLFReadFailed => "toml file read failed",
            HeatmapError::RSLFReadCallLimitReached => {
                "read-call allowance used up (reads kept being interrupted)"
            }
            HeatmapError::RSLFFileExceedsScanLimit => "toml file exceeds RSLF_MAX_BYTES_SCANNED",
            HeatmapError::RSLFFieldNotFound => "no line assigns the key",
            HeatmapError::RSLFValueExceedsOutputBuffer => {
                "value longer than the output buffer; refusing to truncate"
            }
            HeatmapError::RSLFValueUnterminatedAtEndOfFile => {
                "end of file inside a value (no closing quote or no newline)"
            }
            HeatmapError::RSLFKeyMatchIndexInvalid => {
                "key-match position outside the key (internal invariant)"
            }
            HeatmapError::RSLFScanOutcomeMismatch => {
                "scan returned the other goal's result (internal invariant)"
            }
            HeatmapError::RSLFDuplicateKey => "a checked key is assigned on more than one line",
            HeatmapError::TypeScenarioNameInvalid => {
                "scenario name must be 1..=MAX_SCENARIO_NAME_BYTES of A-Z a-z 0-9 _ - ."
            }
            HeatmapError::TypeScenarioNameCorrupted => "ScenarioName failed validity recheck",
            HeatmapError::TypeCargoBinaryNameInvalid => {
                "binary name must be 1..=MAX_CARGO_BINARY_NAME_BYTES of A-Z a-z 0-9 _ - ."
            }
            HeatmapError::TypeCargoBinaryNameCorrupted => "CargoBinaryName failed validity recheck",
            HeatmapError::TypeAnalysisPurposeInvalid => {
                "analysis purpose must be 1..=MAX_ANALYSIS_PURPOSE_BYTES of A-Z a-z 0-9 _ - ."
            }
            HeatmapError::TypeAnalysisPurposeCorrupted => "AnalysisPurpose failed validity recheck",
            HeatmapError::CfgPathNotAbsolute => "config path value is not absolute",
            HeatmapError::CfgPathValueInvalid => {
                "config path value is empty, not UTF-8, longer than MAX_CONFIG_PATH_BYTES, \
                             or contains a double quote, backslash, or control character"
            }
            HeatmapError::CfgPathValueCorrupted => "ConfigPath failed validity recheck",
            HeatmapError::CfgRenderBufferFull => {
                "config text does not fit in CONFIG_FILE_MAX_BYTES (internal invariant)"
            }
            HeatmapError::CfgWriteOpenNotFound => {
                "config file directory not found (create config_files/ first)"
            }
            HeatmapError::CfgWriteOpenPermissionDenied => "config file create: permission denied",
            HeatmapError::CfgWriteOpenTransient => {
                "config file create: transient error (retries exhausted)"
            }
            HeatmapError::CfgWriteOpenAlreadyExists => {
                "config file already exists; refusing to overwrite"
            }
            HeatmapError::CfgWriteOpenOther => "config file create failed",
            HeatmapError::CfgWriteFailed => "writing config file failed",
            HeatmapError::CfgSyncFailed => "syncing config file to disk failed",
            HeatmapError::CfgRoundTripMismatch => {
                "config file read back differs from what was written (internal invariant)"
            }
            HeatmapError::CfgValueLengthInvalid => {
                "field reader returned a length beyond its buffer (internal invariant)"
            }
            HeatmapError::CfgValueNotUtf8 => "config value is not UTF-8",
            HeatmapError::CfgVersionNotANumber => "hix_config_version is not a number",
            HeatmapError::CfgUnsupportedVersion => {
                "hix_config_version is not CONFIG_FORMAT_VERSION of this HIX"
            }
            HeatmapError::CfgTopNInvalid => "config top_n is not a number in 1..=MAX_TOP_N",
            HeatmapError::CfgBooleanInvalid => "config boolean value is not true or false",
            HeatmapError::CfgWorkUnitNameInvalid => {
                "config work_unit_name must be 1..=MAX_WORK_UNIT_NAME_BYTES of A-Z a-z 0-9 _ - ."
            }
            HeatmapError::CfgRenderedRangeInvalid => {
                "rendered config length is outside its buffer (internal invariant)"
            }
        };
        write!(formatter, "HIX-{}: {}", self.code(), description)
    }
}

// ============================================================================
// TOML - Config File Reading
// ============================================================================
// RSLF: Read Single Line Field
// ============================================================================
// Constants (every loop is bounded by these)
// ============================================================================

/// Largest file this module will scan, in bytes (1 MiB).
///
/// Far above any config file in scope. A larger file stops the scan with
/// code 810 instead of running unbounded work on unexpected input.
pub const RSLF_MAX_BYTES_SCANNED: u64 = 1 << 20;

/// Extra read calls allowed for "interrupted" reads (the OS asks the
/// program to try again; nothing is read).
///
/// Every other read call either reads one byte or reports end of file, so
/// the byte limit already bounds those. This allowance keeps the scan loop
/// finite even if a reader reports "interrupted" forever (code 809).
const RSLF_EXTRA_READ_CALLS: u64 = 1024;

/// Tier-1 retry: maximum attempts to open the file on transient errors.
const RSLF_MAX_OPEN_ATTEMPTS: u32 = 3;

/// Tier-1 retry: backoff step in milliseconds (retry n sleeps n * step).
const RSLF_OPEN_RETRY_BACKOFF_STEP_MS: u64 = 50;

// ============================================================================
// Scanner types
// ============================================================================

/// State of the byte-at-a-time line scanner. One state per position class
/// on a line; the current state plus the next byte decides the next state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineScanState {
    /// At the start of the file or just after `\n`.
    AtLineStart,
    /// Inside leading spaces/tabs; same transitions as `AtLineStart`.
    SkippingLeadingWhitespace,
    /// The first `matched_key_bytes` bytes of the key have matched.
    MatchingKey { matched_key_bytes: usize },
    /// The whole key matched; expecting optional spaces/tabs, then `=`.
    AwaitingEquals,
    /// Copy goal only: saw `=`; skipping spaces/tabs before the value.
    AwaitingValueStart,
    /// Copy goal only: inside an unquoted value; ends at `\n`.
    CopyingUnquotedValue,
    /// Copy goal only: inside a quoted value; ends at `"`.
    CopyingQuotedValue,
    /// This line cannot (or no longer needs to) match; skip to `\n`.
    SkippingToEndOfLine,
    /// Comment line (`#` first); skip to `\n`.
    InCommentToEndOfLine,
}

/// What one scan is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanGoal {
    /// Copy the value of the first line that assigns the key, then stop.
    CopyFirstValue,
    /// Count every line that assigns the key; read to the end of the file.
    CountKeyLines,
}

/// Result of a completed scan; the variant matches the `ScanGoal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanOutcome {
    /// Copy goal: the first `written_length` bytes of the output buffer hold the value.
    ValueCopied { written_length: usize },
    /// Count goal: number of lines that assign the key.
    KeyLinesCounted { key_line_count: u32 },
}

/// Everything one scan carries from byte to byte. Fixed size; no heap.
#[derive(Debug)]
struct ScanContext<'key, 'buffer> {
    /// The key, compared in place (never copied).
    key_bytes: &'key [u8],
    scan_goal: ScanGoal,
    /// Caller's output buffer (empty for the count goal).
    output_buffer: &'buffer mut [u8],
    state: LineScanState,
    /// Next write position in `output_buffer` (= value bytes written so far).
    write_cursor: usize,
    /// Unquoted values: a `\r` was seen and is held until the next byte
    /// shows whether it is part of a CRLF ending (dropped) or of the value
    /// (written). Avoids needing a look-ahead buffer.
    unquoted_value_has_pending_cr: bool,
    /// Count goal: lines that assign the key so far. Cannot reach
    /// `u32::MAX`: the file is capped at `RSLF_MAX_BYTES_SCANNED` bytes.
    key_line_count: u32,
}

impl ScanContext<'_, '_> {
    /// Writes one value byte at `write_cursor` and advances it.
    ///
    /// # Returns
    /// - `Ok(())`.
    /// - `Err(RSLFValueExceedsOutputBuffer)` (input validation): the value is
    ///   longer than the output buffer. Nothing is truncated; the caller gets
    ///   no partial value.
    fn push_value_byte(&mut self, value_byte: u8) -> Result<(), HeatmapError> {
        match self.output_buffer.get_mut(self.write_cursor) {
            Some(buffer_slot) => *buffer_slot = value_byte,
            None => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: value longer than output buffer of {} bytes",
                    HeatmapError::RSLFValueExceedsOutputBuffer.code(),
                    self.output_buffer.len()
                );
                return Err(HeatmapError::RSLFValueExceedsOutputBuffer);
            }
        }
        // Cannot overflow: write_cursor < output_buffer.len() was just confirmed.
        self.write_cursor = self.write_cursor.saturating_add(1);
        Ok(())
    }
}

// ============================================================================
// Public functions
// ============================================================================

/// Reads the value of the first line that assigns `target_field_key`,
/// using only stack memory.
///
/// # Project context
/// For reading short config values (paths, names, numbers) at startup with
/// no heap use. The file is read one byte per read call, and only the
/// matched value's bytes are stored. See the module doc for the accepted
/// format and the value-termination policy.
///
/// # Type parameter
/// - `OUTPUT_BUFFER_BYTES`: size of the returned array; the longest value
///   accepted. Must be > 0. Choose the smallest size that fits the field
///   (e.g. 4096 for a Linux path). Longer values return 812, never a
///   truncated value.
///
/// # Arguments
/// - `absolute_toml_file_path`: must be absolute.
/// - `target_field_key`: exact top-level key; must not be empty.
///
/// # Returns
/// - `Ok((buffer, written_length))`: `buffer[..written_length]` is the value;
///   later bytes are 0.
/// - `Err`: 801, 802 (internal invariants); 803-813 (see the error table); 815.
///
/// If the key may appear more than once and that must be an error, call
/// `check_toml_keys_are_unique_no_heap` first; this function returns the first match.
///
/// # Modes
/// Debug builds print diagnostics (may include path and key); 801 and 802
/// also panic in debug builds (not test). Production-release returns codes only.
pub fn read_single_line_field_from_toml_no_heap<const OUTPUT_BUFFER_BYTES: usize>(
    absolute_toml_file_path: &Path,
    target_field_key: &str,
) -> Result<([u8; OUTPUT_BUFFER_BYTES], usize), HeatmapError> {
    // --- Check: output buffer has room for at least one byte ---
    // internal invariant: callers choose a constant size > 0.
    if OUTPUT_BUFFER_BYTES == 0 {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert!(
            false,
            "HIX-{}: OUTPUT_BUFFER_BYTES is 0",
            HeatmapError::RSLFOutputBufferZeroSized.code()
        );
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: OUTPUT_BUFFER_BYTES is 0",
            HeatmapError::RSLFOutputBufferZeroSized.code()
        );
        return Err(HeatmapError::RSLFOutputBufferZeroSized);
    }

    let mut toml_file = open_toml_file_for_scan(absolute_toml_file_path, target_field_key)?;
    let mut output_buffer: [u8; OUTPUT_BUFFER_BYTES] = [0u8; OUTPUT_BUFFER_BYTES];
    let scan_outcome = scan_toml_reader_for_key(
        &mut toml_file,
        target_field_key.as_bytes(),
        ScanGoal::CopyFirstValue,
        &mut output_buffer,
    )?;
    let written_length = copied_value_length_from_outcome(scan_outcome)?;
    Ok((output_buffer, written_length))
}

/// Counts the lines that assign `target_field_key`.
///
/// # Project context
/// Basis of the optional duplicate-key check. A hand-edited config with a
/// key written twice would otherwise silently use the first value.
///
/// A key line is a line whose first non-whitespace bytes are exactly the
/// key, followed by optional spaces/tabs and `=`. Comment lines and longer
/// keys starting with the same bytes are not counted. See the module doc for
/// the multi-line quoted-value limitation.
///
/// # Returns
/// - `Ok(count)`: 0 if the key is not assigned.
/// - `Err`: 801, 803-810, 814, 815 (see the error table).
pub fn count_toml_key_lines_no_heap(
    absolute_toml_file_path: &Path,
    target_field_key: &str,
) -> Result<u32, HeatmapError> {
    let mut toml_file = open_toml_file_for_scan(absolute_toml_file_path, target_field_key)?;
    // The count goal never writes value bytes.
    let mut no_value_buffer: [u8; 0] = [];
    let scan_outcome = scan_toml_reader_for_key(
        &mut toml_file,
        target_field_key.as_bytes(),
        ScanGoal::CountKeyLines,
        &mut no_value_buffer,
    )?;
    key_line_count_from_outcome(scan_outcome)
}

/// Checks that each key in `target_field_keys` is assigned on at most one line.
///
/// # Project context
/// Optional pre-check before reading fields, so that an ambiguous config
/// (a key written twice) stops with a code instead of silently using the
/// first value. Keys not in the list are not checked. A key that is missing
/// is not an error here; the read function reports that (811).
///
/// Opens and scans the file once per key (bounded by the slice length).
///
/// # Returns
/// - `Ok(())`: every listed key appears at most once.
/// - `Err(RSLFDuplicateKey)` (816, input validation): some key appears more
///   than once. The code carries no key; a caller that needs to know which key
///   can call `count_toml_key_lines_no_heap` per key. Debug builds print the key.
/// - Any error from `count_toml_key_lines_no_heap`, unchanged.
pub fn check_toml_keys_are_unique_no_heap(
    absolute_toml_file_path: &Path,
    target_field_keys: &[&str],
) -> Result<(), HeatmapError> {
    for target_field_key in target_field_keys.iter() {
        let key_line_count =
            count_toml_key_lines_no_heap(absolute_toml_file_path, target_field_key)?;
        if key_line_count > 1 {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: key {:?} assigned on {} lines in {}",
                HeatmapError::RSLFDuplicateKey.code(),
                target_field_key,
                key_line_count,
                absolute_toml_file_path.display()
            );
            return Err(HeatmapError::RSLFDuplicateKey);
        }
    }
    Ok(())
}

// ============================================================================
// File opening
// ============================================================================

/// Shared preamble of the public functions: checks the key and path, then
/// opens the file (Tier-1 retry).
///
/// # Returns
/// - `Ok(File)`: unbuffered on purpose (one byte per read call; no heap buffer).
/// - `Err(RSLFEmptyKey)` (internal invariant: callers pass constant keys).
/// - `Err(RSLFPathNotAbsolute)` (input validation).
/// - `Err(804 | 805 | 806 | 807)` from `open_toml_file_with_retry`.
fn open_toml_file_for_scan(
    absolute_toml_file_path: &Path,
    target_field_key: &str,
) -> Result<File, HeatmapError> {
    // --- Check: key is not empty ---
    // internal invariant: an empty key can never match and is a caller bug.
    if target_field_key.is_empty() {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert!(
            false,
            "HIX-{}: empty key",
            HeatmapError::RSLFEmptyKey.code()
        );
        #[cfg(debug_assertions)]
        eprintln!("HIX-{}: empty key", HeatmapError::RSLFEmptyKey.code());
        return Err(HeatmapError::RSLFEmptyKey);
    }

    // --- Check: path is absolute ---
    // input validation: the path comes from the caller's configuration.
    if !absolute_toml_file_path.is_absolute() {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: not absolute: {}",
            HeatmapError::RSLFPathNotAbsolute.code(),
            absolute_toml_file_path.display()
        );
        return Err(HeatmapError::RSLFPathNotAbsolute);
    }

    open_toml_file_with_retry(absolute_toml_file_path)
}

/// Maps an open-error kind to this module's codes. The `io::Error` itself
/// (which may hold path text) is dropped by the caller; only the kind is used.
/// Kinds not listed are "other" (807), which is non-retryable by policy.
fn classify_toml_open_error(io_error_kind: std::io::ErrorKind) -> HeatmapError {
    match io_error_kind {
        std::io::ErrorKind::NotFound => HeatmapError::RSLFOpenNotFound,
        std::io::ErrorKind::PermissionDenied => HeatmapError::RSLFOpenPermissionDenied,
        std::io::ErrorKind::Interrupted
        | std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::TimedOut => HeatmapError::RSLFOpenTransient,
        // Required wildcard: io::ErrorKind is #[non_exhaustive].
        _ => HeatmapError::RSLFOpenOther,
    }
}

/// Opens the file read-only, retrying transient failures (Tier 1).
///
/// Up to `RSLF_MAX_OPEN_ATTEMPTS` attempts; retry n sleeps
/// n * `RSLF_OPEN_RETRY_BACKOFF_STEP_MS`. Non-retryable codes return at once.
///
/// # Returns
/// - `Ok(File)`.
/// - `Err(804 | 805 | 806 | 807)`.
fn open_toml_file_with_retry(absolute_toml_file_path: &Path) -> Result<File, HeatmapError> {
    for attempt_index in 0..RSLF_MAX_OPEN_ATTEMPTS {
        match File::open(absolute_toml_file_path) {
            Ok(opened_file) => return Ok(opened_file),
            Err(io_error) => {
                let error_code = classify_toml_open_error(io_error.kind());
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: open attempt {} failed for {}: {}",
                    error_code.code(),
                    attempt_index,
                    absolute_toml_file_path.display(),
                    io_error
                );
                if !error_code.is_retryable() {
                    return Err(error_code);
                }
                // Last attempt failed: the result is decided, so do not sleep.
                let next_attempt_index = attempt_index.saturating_add(1);
                if next_attempt_index >= RSLF_MAX_OPEN_ATTEMPTS {
                    return Err(error_code);
                }
                let backoff_milliseconds =
                    RSLF_OPEN_RETRY_BACKOFF_STEP_MS.saturating_mul(u64::from(next_attempt_index));
                std::thread::sleep(Duration::from_millis(backoff_milliseconds));
            }
        }
    }
    // Reached only if RSLF_MAX_OPEN_ATTEMPTS is 0 (no attempt was made).
    Err(HeatmapError::RSLFOpenTransient)
}

// ============================================================================
// Scanner
// ============================================================================

/// Scans `toml_reader` one byte per read call for lines that assign the key.
///
/// # Steps (bounded loop)
/// 1. Read one byte. "Interrupted": try again (uses the extra allowance).
///    Any other read error: 808.
/// 2. End of input: finish according to goal and state
///    (`finish_scan_at_end_of_input`).
/// 3. Count the byte; more than `RSLF_MAX_BYTES_SCANNED` bytes: 810.
/// 4. Apply the byte to the state machine (`apply_byte_to_scan`); stop if
///    the copy goal has its value.
///
/// Loop bound: at most `RSLF_MAX_BYTES_SCANNED + 1` byte reads (the last
/// one triggers 810) plus one end-of-input read, plus
/// `RSLF_EXTRA_READ_CALLS` interrupted reads. Reaching the bound: 809.
///
/// # Arguments
/// - `toml_reader`: an unbuffered `File` in production; in-memory input in tests.
/// - `key_bytes`: the key (non-empty; checked by the public functions).
/// - `scan_goal`: copy the first value, or count key lines.
/// - `output_buffer`: value destination (empty slice for the count goal).
///
/// # Returns
/// `Ok(ScanOutcome)` matching the goal, or `Err(808-814)`.
fn scan_toml_reader_for_key<R: Read>(
    toml_reader: &mut R,
    key_bytes: &[u8],
    scan_goal: ScanGoal,
    output_buffer: &mut [u8],
) -> Result<ScanOutcome, HeatmapError> {
    let mut scan = ScanContext {
        key_bytes,
        scan_goal,
        output_buffer,
        state: LineScanState::AtLineStart,
        write_cursor: 0,
        unquoted_value_has_pending_cr: false,
        key_line_count: 0,
    };
    let mut single_byte_scratch: [u8; 1] = [0u8; 1];
    let mut bytes_scanned: u64 = 0;
    let maximum_read_calls = RSLF_MAX_BYTES_SCANNED
        .saturating_add(2)
        .saturating_add(RSLF_EXTRA_READ_CALLS);

    for _read_call_index in 0..maximum_read_calls {
        let bytes_read = match toml_reader.read(&mut single_byte_scratch) {
            Ok(count) => count,
            Err(io_error) if io_error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_io_error) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: read failed: {}",
                    HeatmapError::RSLFReadFailed.code(),
                    _io_error
                );
                return Err(HeatmapError::RSLFReadFailed);
            }
        };
        if bytes_read == 0 {
            return finish_scan_at_end_of_input(&scan);
        }

        bytes_scanned = bytes_scanned.saturating_add(1);
        if bytes_scanned > RSLF_MAX_BYTES_SCANNED {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: file exceeds {} bytes",
                HeatmapError::RSLFFileExceedsScanLimit.code(),
                RSLF_MAX_BYTES_SCANNED
            );
            return Err(HeatmapError::RSLFFileExceedsScanLimit);
        }

        let [current_byte] = single_byte_scratch;
        if let Some(scan_outcome) = apply_byte_to_scan(&mut scan, current_byte)? {
            return Ok(scan_outcome);
        }
    }

    #[cfg(debug_assertions)]
    eprintln!(
        "HIX-{}: read-call limit {} reached",
        HeatmapError::RSLFReadCallLimitReached.code(),
        maximum_read_calls
    );
    Err(HeatmapError::RSLFReadCallLimitReached)
}

/// Applies one input byte to the state machine.
///
/// # Returns
/// - `Ok(None)`: keep scanning.
/// - `Ok(Some(ValueCopied))`: copy goal finished (value terminated).
/// - `Err(RSLFValueExceedsOutputBuffer)`: value longer than the buffer.
/// - `Err(RSLFKeyMatchIndexInvalid)`: internal invariant (see `match_key_byte`).
fn apply_byte_to_scan(
    scan: &mut ScanContext<'_, '_>,
    current_byte: u8,
) -> Result<Option<ScanOutcome>, HeatmapError> {
    match scan.state {
        LineScanState::AtLineStart | LineScanState::SkippingLeadingWhitespace => match current_byte
        {
            b'\n' => scan.state = LineScanState::AtLineStart,
            // A CR at line start (blank CRLF line) is ignored.
            b'\r' => {}
            b' ' | b'\t' => scan.state = LineScanState::SkippingLeadingWhitespace,
            b'#' => scan.state = LineScanState::InCommentToEndOfLine,
            _ => scan.state = match_key_byte(scan.key_bytes, 0, current_byte)?,
        },

        LineScanState::MatchingKey { matched_key_bytes } => {
            scan.state = match_key_byte(scan.key_bytes, matched_key_bytes, current_byte)?;
        }

        LineScanState::AwaitingEquals => match current_byte {
            b' ' | b'\t' => {}
            b'=' => match scan.scan_goal {
                ScanGoal::CopyFirstValue => scan.state = LineScanState::AwaitingValueStart,
                ScanGoal::CountKeyLines => {
                    scan.key_line_count = scan.key_line_count.saturating_add(1);
                    scan.state = LineScanState::SkippingToEndOfLine;
                }
            },
            // Key matched but the line has no `=`: not an assignment.
            b'\n' => scan.state = LineScanState::AtLineStart,
            // E.g. `name_long` when the key is `name`: not this key.
            _ => scan.state = LineScanState::SkippingToEndOfLine,
        },

        LineScanState::AwaitingValueStart => match current_byte {
            b' ' | b'\t' => {}
            b'"' => scan.state = LineScanState::CopyingQuotedValue,
            // `key =` then newline: empty value (write_cursor is 0 here).
            b'\n' => {
                return Ok(Some(ScanOutcome::ValueCopied {
                    written_length: scan.write_cursor,
                }));
            }
            b'\r' => {
                scan.unquoted_value_has_pending_cr = true;
                scan.state = LineScanState::CopyingUnquotedValue;
            }
            _ => {
                scan.push_value_byte(current_byte)?;
                scan.state = LineScanState::CopyingUnquotedValue;
            }
        },

        LineScanState::CopyingUnquotedValue => match current_byte {
            // Terminator; a pending CR is the CR of a CRLF ending and is dropped.
            b'\n' => {
                return Ok(Some(ScanOutcome::ValueCopied {
                    written_length: scan.write_cursor,
                }));
            }
            b'\r' => {
                // A previous pending CR was not followed by LF: it is value data.
                if scan.unquoted_value_has_pending_cr {
                    scan.push_value_byte(b'\r')?;
                }
                scan.unquoted_value_has_pending_cr = true;
            }
            _ => {
                if scan.unquoted_value_has_pending_cr {
                    scan.push_value_byte(b'\r')?;
                    scan.unquoted_value_has_pending_cr = false;
                }
                scan.push_value_byte(current_byte)?;
            }
        },

        LineScanState::CopyingQuotedValue => {
            if current_byte == b'"' {
                return Ok(Some(ScanOutcome::ValueCopied {
                    written_length: scan.write_cursor,
                }));
            }
            scan.push_value_byte(current_byte)?;
        }

        LineScanState::SkippingToEndOfLine | LineScanState::InCommentToEndOfLine => {
            if current_byte == b'\n' {
                scan.state = LineScanState::AtLineStart;
            }
        }
    }
    Ok(None)
}

/// Compares one byte against the key at position `matched_key_bytes`.
///
/// # Returns
/// - `Ok(AwaitingEquals)`: this byte completed the key.
/// - `Ok(MatchingKey { n + 1 })`: matched, key not complete yet.
/// - `Ok(AtLineStart)`: mismatch on `\n` (short line).
/// - `Ok(SkippingToEndOfLine)`: any other mismatch.
/// - `Err(RSLFKeyMatchIndexInvalid)`: `matched_key_bytes` is outside the key.
///   Internal invariant: the state machine only stores positions < key length
///   (an empty key is rejected before scanning).
fn match_key_byte(
    key_bytes: &[u8],
    matched_key_bytes: usize,
    current_byte: u8,
) -> Result<LineScanState, HeatmapError> {
    let expected_key_byte = match key_bytes.get(matched_key_bytes) {
        Some(&key_byte) => key_byte,
        None => {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: key-match position {} outside key of {} bytes",
                HeatmapError::RSLFKeyMatchIndexInvalid.code(),
                matched_key_bytes,
                key_bytes.len()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: key-match position {} outside key of {} bytes",
                HeatmapError::RSLFKeyMatchIndexInvalid.code(),
                matched_key_bytes,
                key_bytes.len()
            );
            return Err(HeatmapError::RSLFKeyMatchIndexInvalid);
        }
    };

    if current_byte == expected_key_byte {
        // Cannot overflow: matched_key_bytes < key_bytes.len() was just confirmed.
        let next_matched_key_bytes = matched_key_bytes.saturating_add(1);
        if next_matched_key_bytes == key_bytes.len() {
            Ok(LineScanState::AwaitingEquals)
        } else {
            Ok(LineScanState::MatchingKey {
                matched_key_bytes: next_matched_key_bytes,
            })
        }
    } else if current_byte == b'\n' {
        Ok(LineScanState::AtLineStart)
    } else {
        Ok(LineScanState::SkippingToEndOfLine)
    }
}

/// Decides the result when the input ends.
///
/// # Returns
/// - Count goal: `Ok(KeyLinesCounted)` in any state.
/// - Copy goal, inside a value or right after `=`:
///   `Err(RSLFValueUnterminatedAtEndOfFile)` (input validation).
/// - Copy goal, any other state: `Err(RSLFFieldNotFound)` (input validation).
fn finish_scan_at_end_of_input(scan: &ScanContext<'_, '_>) -> Result<ScanOutcome, HeatmapError> {
    match scan.scan_goal {
        ScanGoal::CountKeyLines => Ok(ScanOutcome::KeyLinesCounted {
            key_line_count: scan.key_line_count,
        }),
        ScanGoal::CopyFirstValue => match scan.state {
            LineScanState::AwaitingValueStart
            | LineScanState::CopyingUnquotedValue
            | LineScanState::CopyingQuotedValue => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: end of file inside value of key {:?}",
                    HeatmapError::RSLFValueUnterminatedAtEndOfFile.code(),
                    String::from_utf8_lossy(scan.key_bytes)
                );
                Err(HeatmapError::RSLFValueUnterminatedAtEndOfFile)
            }
            LineScanState::AtLineStart
            | LineScanState::SkippingLeadingWhitespace
            | LineScanState::MatchingKey { .. }
            | LineScanState::AwaitingEquals
            | LineScanState::SkippingToEndOfLine
            | LineScanState::InCommentToEndOfLine => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: key {:?} not found",
                    HeatmapError::RSLFFieldNotFound.code(),
                    String::from_utf8_lossy(scan.key_bytes)
                );
                Err(HeatmapError::RSLFFieldNotFound)
            }
        },
    }
}

/// Extracts the value length from a copy-goal outcome.
/// `Err(RSLFScanOutcomeMismatch)`: internal invariant (a count result
/// returned for a copy scan).
fn copied_value_length_from_outcome(scan_outcome: ScanOutcome) -> Result<usize, HeatmapError> {
    match scan_outcome {
        ScanOutcome::ValueCopied { written_length } => Ok(written_length),
        ScanOutcome::KeyLinesCounted { .. } => {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: copy scan returned a count",
                HeatmapError::RSLFScanOutcomeMismatch.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: copy scan returned a count",
                HeatmapError::RSLFScanOutcomeMismatch.code()
            );
            Err(HeatmapError::RSLFScanOutcomeMismatch)
        }
    }
}

/// Extracts the key-line count from a count-goal outcome.
/// `Err(RSLFScanOutcomeMismatch)`: internal invariant (a copied value
/// returned for a count scan).
fn key_line_count_from_outcome(scan_outcome: ScanOutcome) -> Result<u32, HeatmapError> {
    match scan_outcome {
        ScanOutcome::KeyLinesCounted { key_line_count } => Ok(key_line_count),
        ScanOutcome::ValueCopied { .. } => {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: count scan returned a value",
                HeatmapError::RSLFScanOutcomeMismatch.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: count scan returned a value",
                HeatmapError::RSLFScanOutcomeMismatch.code()
            );
            Err(HeatmapError::RSLFScanOutcomeMismatch)
        }
    }
}

// ============================================================================
// Tests (test mode only)
// ============================================================================

/*
Default test.toml

```toml
text = "production"
longtext = "productionproductionproductionproductionproductionproductionproduction"
```
*/

/// Unit tests (compiled only under `cargo test`).
///
/// Scanner tests run `scan_toml_reader_for_key` on in-memory input
/// (`Cursor`, `io::repeat`, and small failing readers), so they create no
/// files. Tests of the public functions create uniquely named files under
/// `std::env::temp_dir()` and remove them at the end; if such a test fails
/// mid-way its file may remain (harmless, unique name).
///
/// Test names: `rslf_<area>_<condition>[_with_code_<nnn>]`.
/// Areas: `scan`, `count`, `read`, `unique`, `err`, `guard`.
/// `unwrap`/`assert!`/indexing are allowed here (test mode).
#[cfg(test)]
mod read_toml_single_line_field_no_heap_tests {
    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    /// Runs a copy-goal scan on `toml_text` with a `buffer_length`-byte
    /// output buffer; returns the copied value bytes.
    fn copy_first_value(
        toml_text: &str,
        key: &str,
        buffer_length: usize,
    ) -> Result<Vec<u8>, HeatmapError> {
        let mut output_buffer = vec![0u8; buffer_length];
        let mut toml_reader = Cursor::new(toml_text.as_bytes());
        match scan_toml_reader_for_key(
            &mut toml_reader,
            key.as_bytes(),
            ScanGoal::CopyFirstValue,
            &mut output_buffer,
        )? {
            ScanOutcome::ValueCopied { written_length } => {
                Ok(output_buffer[..written_length].to_vec())
            }
            ScanOutcome::KeyLinesCounted { .. } => panic!("copy scan returned a count"),
        }
    }

    /// Runs a count-goal scan on `toml_text`; returns the key-line count.
    fn count_key_lines(toml_text: &str, key: &str) -> Result<u32, HeatmapError> {
        let mut toml_reader = Cursor::new(toml_text.as_bytes());
        let mut no_value_buffer: [u8; 0] = [];
        match scan_toml_reader_for_key(
            &mut toml_reader,
            key.as_bytes(),
            ScanGoal::CountKeyLines,
            &mut no_value_buffer,
        )? {
            ScanOutcome::KeyLinesCounted { key_line_count } => Ok(key_line_count),
            ScanOutcome::ValueCopied { .. } => panic!("count scan returned a value"),
        }
    }

    /// Writes `contents` to a uniquely named file under the temp dir and
    /// returns its absolute path. The caller removes the file.
    fn write_unique_temp_toml(label: &str, contents: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rslf_test_{}_{}_{}.toml",
            label,
            std::process::id(),
            nanos
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// Reader that reports "interrupted" before every real read.
    struct InterruptEveryOtherRead {
        inner: Cursor<Vec<u8>>,
        interrupt_next: bool,
    }

    impl Read for InterruptEveryOtherRead {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.interrupt_next {
                self.interrupt_next = false;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            self.interrupt_next = true;
            self.inner.read(buffer)
        }
    }

    /// Reader that reports "interrupted" forever.
    struct AlwaysInterruptedReader;

    impl Read for AlwaysInterruptedReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        }
    }

    /// Reader whose every read fails with a non-retryable error.
    struct AlwaysFailingReader;

    impl Read for AlwaysFailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::Other))
        }
    }

    /// Basic case: a quoted value is copied without its quotes.
    #[test]
    fn rslf_scan_copies_quoted_value() {
        assert_eq!(
            copy_first_value("name = \"alice\"\n", "name", 16).unwrap(),
            b"alice"
        );
    }

    /// Unquoted values (numbers, bare words) end at the newline.
    #[test]
    fn rslf_scan_copies_unquoted_value() {
        assert_eq!(
            copy_first_value("port = 8080\n", "port", 16).unwrap(),
            b"8080"
        );
    }

    /// CRLF files: the quoted value is unaffected by the CR.
    #[test]
    fn rslf_scan_handles_crlf_for_quoted_value() {
        let value = copy_first_value("name = \"bob\"\r\nother = \"x\"\r\n", "name", 16).unwrap();
        assert_eq!(value, b"bob");
    }

    /// CRLF files: the CR before LF is not part of an unquoted value.
    #[test]
    fn rslf_scan_handles_crlf_for_unquoted_value() {
        assert_eq!(
            copy_first_value("port = 8080\r\nx = 1\r\n", "port", 16).unwrap(),
            b"8080"
        );
    }

    /// Comment lines (also indented) and blank lines are skipped.
    #[test]
    fn rslf_scan_skips_comments_and_blank_lines() {
        let toml_text = "# header\n\n   # indented comment\nname = \"carol\"\n";
        assert_eq!(copy_first_value(toml_text, "name", 16).unwrap(), b"carol");
    }

    /// A longer key that starts with the requested key is not a match.
    #[test]
    fn rslf_scan_does_not_match_longer_key_with_same_prefix() {
        let toml_text = "name_long = \"WRONG\"\nname = \"RIGHT\"\n";
        assert_eq!(copy_first_value(toml_text, "name", 16).unwrap(), b"RIGHT");
    }

    /// A key that no line assigns is reported, not defaulted.
    #[test]
    fn rslf_scan_missing_key_with_code_811() {
        let error = copy_first_value("other = \"x\"\n", "name", 16).unwrap_err();
        assert_eq!(error, HeatmapError::RSLFFieldNotFound);
        assert_eq!(error.code(), 811);
    }

    /// A value longer than the buffer (9 bytes into 8) is refused, never truncated.
    #[test]
    fn rslf_scan_value_longer_than_buffer_with_code_812() {
        let error = copy_first_value("name = \"toolongxx\"\n", "name", 8).unwrap_err();
        assert_eq!(error, HeatmapError::RSLFValueExceedsOutputBuffer);
        assert_eq!(error.code(), 812);
    }

    /// A quoted value needs no trailing newline: the closing quote ends it.
    #[test]
    fn rslf_scan_quoted_value_at_end_of_file_is_complete() {
        assert_eq!(
            copy_first_value("name = \"dora\"", "name", 16).unwrap(),
            b"dora"
        );
    }

    /// An unquoted value without a trailing newline is incomplete (policy:
    /// unquoted values need `\n`, as quoted values need `"`).
    #[test]
    fn rslf_scan_unquoted_value_without_newline_with_code_813() {
        let error = copy_first_value("port = 8080", "port", 16).unwrap_err();
        assert_eq!(error, HeatmapError::RSLFValueUnterminatedAtEndOfFile);
        assert_eq!(error.code(), 813);
    }

    /// A quoted value without a closing quote reads through the newline to
    /// end of file and is reported as incomplete.
    #[test]
    fn rslf_scan_quoted_value_without_closing_quote_with_code_813() {
        let error = copy_first_value("name = \"alice\n", "name", 16).unwrap_err();
        assert_eq!(error, HeatmapError::RSLFValueUnterminatedAtEndOfFile);
    }

    /// The key is found after many unrelated lines.
    #[test]
    fn rslf_scan_finds_key_after_many_lines() {
        let mut toml_text = String::new();
        for line_index in 0..200 {
            toml_text.push_str(&format!("noise_key_{:03} = \"junkjunkjunk\"\n", line_index));
        }
        toml_text.push_str("target = \"eve\"\n");
        assert_eq!(copy_first_value(&toml_text, "target", 16).unwrap(), b"eve");
    }

    /// An unrelated line far longer than the output buffer does not stop the
    /// scan: only the matched value is stored.
    #[test]
    fn rslf_scan_unrelated_long_line_does_not_stop_scan() {
        let toml_text = format!("other_key = \"{}\"\nname = \"frank\"\n", "X".repeat(4096));
        assert_eq!(copy_first_value(&toml_text, "name", 16).unwrap(), b"frank");
    }

    /// Spaces and tabs are allowed before the key and around `=`.
    #[test]
    fn rslf_scan_allows_whitespace_around_key_and_equals() {
        let value = copy_first_value("   name\t=\t  \"grace\"   \n", "name", 16).unwrap();
        assert_eq!(value, b"grace");
    }

    /// The read returns the first assignment (duplicates are the optional
    /// uniqueness check's job).
    #[test]
    fn rslf_scan_first_assignment_wins() {
        let value = copy_first_value("name = \"first\"\nname = \"second\"\n", "name", 16).unwrap();
        assert_eq!(value, b"first");
    }

    /// Policy: spaces before the newline are part of an unquoted value.
    #[test]
    fn rslf_scan_unquoted_value_keeps_trailing_whitespace() {
        assert_eq!(
            copy_first_value("port = 8080   \n", "port", 16).unwrap(),
            b"8080   "
        );
    }

    /// `key =` then newline is an empty value, not an error.
    #[test]
    fn rslf_scan_empty_unquoted_value_is_empty() {
        assert!(
            copy_first_value("name = \n", "name", 16)
                .unwrap()
                .is_empty()
        );
    }

    /// `key = ""` is an empty value.
    #[test]
    fn rslf_scan_empty_quoted_value_is_empty() {
        assert!(
            copy_first_value("name = \"\"\n", "name", 16)
                .unwrap()
                .is_empty()
        );
    }

    /// A one-byte key completes on its first byte (general match path).
    #[test]
    fn rslf_scan_single_byte_key() {
        assert_eq!(copy_first_value("x = \"yes\"\n", "x", 16).unwrap(), b"yes");
    }

    /// Interrupted reads are retried, and the result is unchanged.
    #[test]
    fn rslf_scan_retries_interrupted_reads() {
        let mut toml_reader = InterruptEveryOtherRead {
            inner: Cursor::new(b"name = \"ivy\"\n".to_vec()),
            interrupt_next: true,
        };
        let mut output_buffer = [0u8; 16];
        let outcome = scan_toml_reader_for_key(
            &mut toml_reader,
            b"name",
            ScanGoal::CopyFirstValue,
            &mut output_buffer,
        )
        .unwrap();
        assert_eq!(outcome, ScanOutcome::ValueCopied { written_length: 3 });
        assert_eq!(&output_buffer[..3], b"ivy");
    }

    /// Endless interruptions end at the read-call bound instead of looping forever.
    #[test]
    fn rslf_scan_endless_interruptions_with_code_809() {
        let mut output_buffer = [0u8; 16];
        let error = scan_toml_reader_for_key(
            &mut AlwaysInterruptedReader,
            b"name",
            ScanGoal::CopyFirstValue,
            &mut output_buffer,
        )
        .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFReadCallLimitReached);
        assert_eq!(error.code(), 809);
    }

    /// A failing read stops the scan with its own code.
    #[test]
    fn rslf_scan_read_failure_with_code_808() {
        let mut output_buffer = [0u8; 16];
        let error = scan_toml_reader_for_key(
            &mut AlwaysFailingReader,
            b"name",
            ScanGoal::CopyFirstValue,
            &mut output_buffer,
        )
        .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFReadFailed);
        assert_eq!(error.code(), 808);
    }

    /// Input larger than the scan limit (here: endless) stops at the byte cap.
    #[test]
    fn rslf_scan_input_exceeds_limit_with_code_810() {
        let mut endless_input = std::io::repeat(b'x');
        let mut output_buffer = [0u8; 16];
        let error = scan_toml_reader_for_key(
            &mut endless_input,
            b"name",
            ScanGoal::CopyFirstValue,
            &mut output_buffer,
        )
        .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFFileExceedsScanLimit);
        assert_eq!(error.code(), 810);
    }

    /// Key-line counting: assignments are counted; comments, longer keys,
    /// and lines without `=` are not; indented assignments are.
    #[test]
    fn rslf_count_counts_only_assignment_lines() {
        let toml_text = "name = \"a\"\n# name = \"b\"\nname_long = \"c\"\nname\n  name=\"d\"\n";
        assert_eq!(count_key_lines(toml_text, "name").unwrap(), 2);
        assert_eq!(count_key_lines(toml_text, "absent").unwrap(), 0);
    }

    /// Invariant catch: a key-match position outside the key (state built
    /// directly, simulating corruption) is rejected, not indexed.
    #[test]
    fn rslf_scan_corrupt_match_position_with_code_814() {
        let mut no_value_buffer: [u8; 0] = [];
        let mut scan = ScanContext {
            key_bytes: b"name",
            scan_goal: ScanGoal::CopyFirstValue,
            output_buffer: &mut no_value_buffer,
            state: LineScanState::MatchingKey {
                matched_key_bytes: 99,
            },
            write_cursor: 0,
            unquoted_value_has_pending_cr: false,
            key_line_count: 0,
        };
        let error = apply_byte_to_scan(&mut scan, b'a').unwrap_err();
        assert_eq!(error, HeatmapError::RSLFKeyMatchIndexInvalid);
        assert_eq!(error.code(), 814);
    }

    /// Invariant catch: each goal's extractor rejects the other goal's result.
    #[test]
    fn rslf_scan_outcome_mismatch_with_code_815() {
        let error =
            copied_value_length_from_outcome(ScanOutcome::KeyLinesCounted { key_line_count: 1 })
                .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFScanOutcomeMismatch);
        assert_eq!(error.code(), 815);
        assert_eq!(
            key_line_count_from_outcome(ScanOutcome::ValueCopied { written_length: 0 })
                .unwrap_err(),
            HeatmapError::RSLFScanOutcomeMismatch
        );
    }

    /// End to end on a real file: value read; later buffer bytes are 0.
    #[test]
    fn rslf_read_reads_value_from_file() {
        let path = write_unique_temp_toml("read_ok", "mode = \"production\"\nport = 8080\n");
        let (output_buffer, written_length) =
            read_single_line_field_from_toml_no_heap::<16>(&path, "mode").unwrap();
        assert_eq!(&output_buffer[..written_length], b"production");
        assert!(
            output_buffer[written_length..]
                .iter()
                .all(|byte| *byte == 0)
        );
        std::fs::remove_file(&path).unwrap();
    }

    /// A relative path is refused before any file access.
    #[test]
    fn rslf_read_relative_path_with_code_803() {
        let error = read_single_line_field_from_toml_no_heap::<16>(
            Path::new("relative/config.toml"),
            "name",
        )
        .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFPathNotAbsolute);
        assert_eq!(error.code(), 803);
    }

    /// A missing file fails fast (not retryable, no backoff sleeps).
    #[test]
    fn rslf_read_missing_file_with_code_804() {
        let error = read_single_line_field_from_toml_no_heap::<16>(
            Path::new("/nonexistent_rslf_test_dir/missing.toml"),
            "name",
        )
        .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFOpenNotFound);
        assert_eq!(error.code(), 804);
        assert!(!error.is_retryable());
    }

    /// An empty key is refused before the path is checked or opened.
    #[test]
    fn rslf_read_empty_key_with_code_801() {
        let error = read_single_line_field_from_toml_no_heap::<16>(
            Path::new("/nonexistent_rslf_test_dir/any.toml"),
            "",
        )
        .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFEmptyKey);
        assert_eq!(error.code(), 801);
    }

    /// A zero-size output buffer is refused before any file access.
    #[test]
    fn rslf_read_zero_size_buffer_with_code_802() {
        let error = read_single_line_field_from_toml_no_heap::<0>(
            Path::new("/nonexistent_rslf_test_dir/any.toml"),
            "name",
        )
        .unwrap_err();
        assert_eq!(error, HeatmapError::RSLFOutputBufferZeroSized);
        assert_eq!(error.code(), 802);
    }

    /// Uniqueness check on a real file: unique keys pass, a key assigned
    /// twice returns 816, and the per-key count shows which key.
    #[test]
    fn rslf_unique_duplicate_key_with_code_816() {
        let path = write_unique_temp_toml("unique", "mode = \"a\"\nport = 1\nmode = \"b\"\n");
        assert!(check_toml_keys_are_unique_no_heap(&path, &["port"]).is_ok());
        let error = check_toml_keys_are_unique_no_heap(&path, &["port", "mode"]).unwrap_err();
        assert_eq!(error, HeatmapError::RSLFDuplicateKey);
        assert_eq!(error.code(), 816);
        assert_eq!(count_toml_key_lines_no_heap(&path, "mode").unwrap(), 2);
        std::fs::remove_file(&path).unwrap();
    }

    /// Retry policy is per code: only the transient open code retries.
    #[test]
    fn rslf_err_is_retryable_only_transient_open() {
        assert!(HeatmapError::RSLFOpenTransient.is_retryable());
        assert!(!HeatmapError::RSLFOpenNotFound.is_retryable());
        assert!(!HeatmapError::RSLFReadCallLimitReached.is_retryable());
    }

    /// Single source of truth for code numbers: no message may contain the
    /// marker followed by a digit; numbers come only from `.code()`.
    #[test]
    fn rslf_guard_source_contains_no_hard_coded_error_code_numbers() {
        let source_files: [(&str, &str); 2] = [
            (
                "hix_heatmap_indices_for_compute.rs",
                include_str!("hix_heatmap_indices_for_compute.rs"),
            ),
            ("main.rs", include_str!("main.rs")),
        ];
        let marker = "RSLF-";
        for (file_name, source_text) in source_files.iter() {
            for (line_index, line_text) in source_text.lines().enumerate() {
                for (found_index, _) in line_text.match_indices(marker) {
                    let byte_after_marker = line_text.as_bytes().get(found_index + marker.len());
                    assert!(
                        !matches!(byte_after_marker, Some(byte) if byte.is_ascii_digit()),
                        "{}:{}: hard-coded error-code number: {}",
                        file_name,
                        line_index + 1,
                        line_text.trim()
                    );
                }
            }
        }
    }
}

// ============================================================================
// HIX config files (run configuration in the TOML subset)
// ============================================================================
//
// A config file holds what is needed to repeat a run. It is written by the
// wizard (create-new, never overwritten), then read back and compared, and
// it is read by the wizard and by automated replay. Each field is read with
// `read_single_line_field_from_toml_no_heap` (no heap).
//
// File layout (exactly as written by `render_config_file_text`):
//   # two comment lines
//   hix_config_version = 1
//   target_crate_path = "/ABSOLUTE/path/to/target/crate"
//   target_binary_name = "pumpkin"
//   modeling_data_path = "/ABSOLUTE/path/to/modeling_data"
//   scenario_name = "pumpkin_world_spawn"
//   analysis_purpose = "count_baseline"
//   top_n = 20
//   work_unit_name = "chunks_generated"     <- line omitted when not set
//   demangle_outputs = true
//
// Reading rules (`load_config_file`):
// - Each known key may appear at most once (816).
// - `hix_config_version` must equal `CONFIG_FORMAT_VERSION` (831, 832).
// - Every key except `work_unit_name` is required (811 if missing).
// - Unknown keys are ignored: the field reader looks up known keys only.
// - Numbers and booleans may have spaces around them; quoted values are
//   taken exactly as written.
//
// The work-unit COUNT is not stored here: it is a result of each run, entered
// after the run, and belongs in that run's record.

/// Format version written to and required from every config file.
/// Raise it when a change to keys or their meaning would make an older HIX
/// misread a newer file (or the reverse); an unequal version is refused (832).
const CONFIG_FORMAT_VERSION: u32 = 1;

/// Longest path value accepted in a config file, in bytes.
///
/// 4096 is the Linux `PATH_MAX`. If a longer path is ever needed, raise this
/// constant; the config render buffer (`CONFIG_FILE_MAX_BYTES`) and the
/// path-read buffer (this constant, as a const generic) follow it
/// automatically. Both are stack arrays.
const MAX_CONFIG_PATH_BYTES: usize = 4096;

/// Stack buffer for rendering one config file: the two path values at their
/// maximum length plus a fixed allowance for comments, keys, and the short
/// fields. The test `cfg_write_new_config_file_longest_values_round_trip`
/// renders a config with every field at its maximum length.
const CONFIG_FILE_MAX_BYTES: usize = 2 * MAX_CONFIG_PATH_BYTES + 4096;

/// Stack buffer for reading short config values (names, numbers, booleans).
/// At least as long as every short field's maximum (compile-time check below).
const CONFIG_SHORT_VALUE_BUFFER_BYTES: usize = 128;

/// Longest scenario name (the `<scenario>` in `run_NNN_<scenario>`).
const MAX_SCENARIO_NAME_BYTES: usize = 96;

/// Longest cargo binary name (passed to `--bin`; cargo validates it further).
const MAX_CARGO_BINARY_NAME_BYTES: usize = 64;

/// Longest analysis purpose (the `<purpose>` in `analysis_NNN_<purpose>`).
const MAX_ANALYSIS_PURPOSE_BYTES: usize = 64;

// Compile-time guard: a run folder name `run_NNNN_<scenario>` (run numbers
// up to 9999) fits in a run label, so the folder name can be passed to the
// analysis as `--run-label` unchanged.
const _: () = assert!("run_9999_".len() + MAX_SCENARIO_NAME_BYTES <= MAX_RUN_LABEL_BYTES);

// Compile-time guard: the short-value read buffer holds every short field at
// its maximum, so an over-long hand-edited name reaches its own type's check.
const _: () = assert!(
    CONFIG_SHORT_VALUE_BUFFER_BYTES >= MAX_SCENARIO_NAME_BYTES
        && CONFIG_SHORT_VALUE_BUFFER_BYTES >= MAX_CARGO_BINARY_NAME_BYTES
        && CONFIG_SHORT_VALUE_BUFFER_BYTES >= MAX_ANALYSIS_PURPOSE_BYTES
        && CONFIG_SHORT_VALUE_BUFFER_BYTES >= MAX_WORK_UNIT_NAME_BYTES
);

/// Config file names: `hix_<scenario>.toml`.
const CONFIG_FILE_NAME_PREFIX: &str = "hix_";
const CONFIG_FILE_NAME_SUFFIX: &str = ".toml";

/// Config keys (the only place each key's text is written).
const CONFIG_KEY_FORMAT_VERSION: &str = "hix_config_version";
const CONFIG_KEY_TARGET_CRATE_PATH: &str = "target_crate_path";
const CONFIG_KEY_TARGET_BINARY_NAME: &str = "target_binary_name";
const CONFIG_KEY_MODELING_DATA_PATH: &str = "modeling_data_path";
const CONFIG_KEY_SCENARIO_NAME: &str = "scenario_name";
const CONFIG_KEY_ANALYSIS_PURPOSE: &str = "analysis_purpose";
const CONFIG_KEY_TOP_N: &str = "top_n";
const CONFIG_KEY_WORK_UNIT_NAME: &str = "work_unit_name";
const CONFIG_KEY_DEMANGLE_OUTPUTS: &str = "demangle_outputs";

/// Number of config keys.
const CONFIG_KEY_COUNT: usize = 9;

/// Every config key: checked for duplicates before any field is read.
/// The test `cfg_render_config_file_text_writes_every_key_once` keeps this
/// list and the writer in step.
const CONFIG_KEYS: [&str; CONFIG_KEY_COUNT] = [
    CONFIG_KEY_FORMAT_VERSION,
    CONFIG_KEY_TARGET_CRATE_PATH,
    CONFIG_KEY_TARGET_BINARY_NAME,
    CONFIG_KEY_MODELING_DATA_PATH,
    CONFIG_KEY_SCENARIO_NAME,
    CONFIG_KEY_ANALYSIS_PURPOSE,
    CONFIG_KEY_TOP_N,
    CONFIG_KEY_WORK_UNIT_NAME,
    CONFIG_KEY_DEMANGLE_OUTPUTS,
];

/// Open-error codes for creating a config file (create-new: never overwrites).
const CONFIG_WRITE_OPEN_ERROR_CODES: OpenErrorCodes = OpenErrorCodes {
    not_found: HeatmapError::CfgWriteOpenNotFound,
    permission_denied: HeatmapError::CfgWriteOpenPermissionDenied,
    transient: HeatmapError::CfgWriteOpenTransient,
    already_exists: HeatmapError::CfgWriteOpenAlreadyExists,
    other: HeatmapError::CfgWriteOpenOther,
};

// ----------------------------------------------------------------------------
// Short names: one rule, one type per meaning, unique codes per kind
// ----------------------------------------------------------------------------

/// Rules for one kind of short name used in config files and folder names.
///
/// Every kind uses the run-label character rule (`is_valid_metadata_text`:
/// 1..=max bytes of `A-Z a-z 0-9 _ - .`). So a name is safe as a quoted
/// config value (no quotes or backslashes), in the report and TSV, and as
/// part of a folder name. Kinds differ only in maximum length and in their
/// error codes, which stay unique per kind so a code points at its field.
pub trait NameTextKind {
    /// Longest accepted name, in bytes (ASCII only, so also characters).
    const MAX_BYTES: usize;
    /// Returned by `NameText::new` for a name that breaks the rule (input validation).
    const INVALID_CODE: HeatmapError;
    /// Returned by `NameText::get` when a stored name fails its recheck (internal invariant).
    const CORRUPTED_CODE: HeatmapError;
    /// Field name, used only by debug-build diagnostics.
    const FIELD_LABEL: &'static str;
}

/// Kind marker: scenario name (`run_NNN_<scenario>`, `hix_<scenario>.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioNameKind;

impl NameTextKind for ScenarioNameKind {
    const MAX_BYTES: usize = MAX_SCENARIO_NAME_BYTES;
    const INVALID_CODE: HeatmapError = HeatmapError::TypeScenarioNameInvalid;
    const CORRUPTED_CODE: HeatmapError = HeatmapError::TypeScenarioNameCorrupted;
    const FIELD_LABEL: &'static str = "scenario name";
}

/// Kind marker: cargo binary name (`cargo llvm-cov run --bin <name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CargoBinaryNameKind;

impl NameTextKind for CargoBinaryNameKind {
    const MAX_BYTES: usize = MAX_CARGO_BINARY_NAME_BYTES;
    const INVALID_CODE: HeatmapError = HeatmapError::TypeCargoBinaryNameInvalid;
    const CORRUPTED_CODE: HeatmapError = HeatmapError::TypeCargoBinaryNameCorrupted;
    const FIELD_LABEL: &'static str = "cargo binary name";
}

/// Kind marker: analysis purpose (`analysis_NNN_<purpose>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisPurposeKind;

impl NameTextKind for AnalysisPurposeKind {
    const MAX_BYTES: usize = MAX_ANALYSIS_PURPOSE_BYTES;
    const INVALID_CODE: HeatmapError = HeatmapError::TypeAnalysisPurposeInvalid;
    const CORRUPTED_CODE: HeatmapError = HeatmapError::TypeAnalysisPurposeCorrupted;
    const FIELD_LABEL: &'static str = "analysis purpose";
}

/// A short name of kind `K`, validated on construction and rechecked on read.
/// Use the aliases `ScenarioName`, `CargoBinaryName`, `AnalysisPurpose`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameText<K: NameTextKind> {
    name_text: String,
    kind: PhantomData<K>,
}

/// Scenario name, e.g. `pumpkin_world_spawn`.
pub type ScenarioName = NameText<ScenarioNameKind>;
/// Cargo binary name, e.g. `pumpkin`.
pub type CargoBinaryName = NameText<CargoBinaryNameKind>;
/// Analysis purpose, e.g. `count_baseline`.
pub type AnalysisPurpose = NameText<AnalysisPurposeKind>;

impl<K: NameTextKind> NameText<K> {
    /// Validates and constructs.
    ///
    /// # Returns
    /// - `Ok(NameText)`.
    /// - `Err(K::INVALID_CODE)` (input validation: names come from the user or
    ///   from a hand-editable config file): empty, longer than `K::MAX_BYTES`,
    ///   or a byte outside `A-Z a-z 0-9 _ - .`.
    ///
    /// # Modes
    /// Debug builds print the field and the rejected text.
    pub fn ntk_new(candidate_text: &str) -> Result<Self, HeatmapError> {
        if !is_valid_metadata_text(candidate_text, K::MAX_BYTES) {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: invalid {} {:?} (1..={} of A-Z a-z 0-9 _ - .)",
                K::INVALID_CODE.code(),
                K::FIELD_LABEL,
                candidate_text,
                K::MAX_BYTES
            );
            return Err(K::INVALID_CODE);
        }
        Ok(Self {
            name_text: candidate_text.to_string(),
            kind: PhantomData,
        })
    }

    /// Returns the name after rechecking it.
    ///
    /// # Returns
    /// - `Ok(&str)`.
    /// - `Err(K::CORRUPTED_CODE)` (internal invariant: `new` already checked
    ///   the same rule, so a failure here means corrupted memory or a value
    ///   built without `new`).
    pub fn ntk_get(&self) -> Result<&str, HeatmapError> {
        if !is_valid_metadata_text(&self.name_text, K::MAX_BYTES) {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: {} corrupted",
                K::CORRUPTED_CODE.code(),
                K::FIELD_LABEL
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: {} recheck failed",
                K::CORRUPTED_CODE.code(),
                K::FIELD_LABEL
            );
            return Err(K::CORRUPTED_CODE);
        }
        Ok(self.name_text.as_str())
    }
}

// ----------------------------------------------------------------------------
// Path values 1
// ----------------------------------------------------------------------------

/// True if `candidate_text` can be stored as a quoted config value and read
/// back unchanged: 1..=`MAX_CONFIG_PATH_BYTES` bytes, with no `"` (would end
/// the value), no `\` (an escape in real TOML; refused so files stay valid
/// TOML), and no control bytes (0x00-0x1F, 0x7F; a newline would split the line).
/// Non-ASCII UTF-8 is allowed.
fn is_valid_config_path_text(candidate_text: &str) -> bool {
    !candidate_text.is_empty()
        && candidate_text.len() <= MAX_CONFIG_PATH_BYTES
        && candidate_text
            .bytes()
            .all(|byte| byte != b'"' && byte != b'\\' && byte >= 0x20 && byte != 0x7F)
}

/// An absolute path that can be written to a config file and read back
/// unchanged (see `is_valid_config_path_text`). Stored as text, because a
/// config file is text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPath {
    path_text: String,
}

impl ConfigPath {
    /// Validates and constructs.
    ///
    /// # Returns
    /// - `Ok(ConfigPath)`.
    /// - `Err(CfgPathValueInvalid)` (input validation): not UTF-8, empty,
    ///   too long, or contains `"`, `\`, or a control byte.
    /// - `Err(CfgPathNotAbsolute)` (input validation).
    ///
    /// # Modes
    /// Debug builds print the rejected path.
    pub fn cp_new(candidate_path: &Path) -> Result<Self, HeatmapError> {
        let candidate_text = match candidate_path.to_str() {
            Some(text) => text,
            None => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: config path is not UTF-8: {}",
                    HeatmapError::CfgPathValueInvalid.code(),
                    candidate_path.display()
                );
                return Err(HeatmapError::CfgPathValueInvalid);
            }
        };
        if !candidate_path.is_absolute() {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: config path is not absolute: {:?}",
                HeatmapError::CfgPathNotAbsolute.code(),
                candidate_text
            );
            return Err(HeatmapError::CfgPathNotAbsolute);
        }
        if !is_valid_config_path_text(candidate_text) {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: config path not storable ({} bytes; max {}; no \" \\ or control bytes): {:?}",
                HeatmapError::CfgPathValueInvalid.code(),
                candidate_text.len(),
                MAX_CONFIG_PATH_BYTES,
                candidate_text
            );
            return Err(HeatmapError::CfgPathValueInvalid);
        }
        Ok(Self {
            path_text: candidate_text.to_string(),
        })
    }

    /// Returns the path text after rechecking it (used by the config writer).
    ///
    /// # Returns
    /// - `Ok(&str)`.
    /// - `Err(CfgPathValueCorrupted)` (internal invariant: `new` checked the same rules).
    pub fn cp_get_text(&self) -> Result<&str, HeatmapError> {
        let is_intact =
            is_valid_config_path_text(&self.path_text) && Path::new(&self.path_text).is_absolute();
        if !is_intact {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: ConfigPath corrupted",
                HeatmapError::CfgPathValueCorrupted.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: ConfigPath recheck failed",
                HeatmapError::CfgPathValueCorrupted.code()
            );
            return Err(HeatmapError::CfgPathValueCorrupted);
        }
        Ok(self.path_text.as_str())
    }

    /// Returns the path after rechecking it. Same errors as `get_text`.
    pub fn cp_get(&self) -> Result<&Path, HeatmapError> {
        Ok(Path::new(self.cp_get_text()?))
    }
}

// ----------------------------------------------------------------------------
// Path values 2
// ----------------------------------------------------------------------------

/// True if `candidate_text` can be written as a quoted config value and read
/// back byte for byte by the config field reader.
///
/// This checks the characters of the path itself. It does not touch the
/// filesystem: the path need not exist.
///
/// Rules, and why each exists:
/// - 1..=`MAX_CONFIG_PATH_BYTES` bytes: the read buffer for path fields has
///   exactly this size, so a longer value would be refused when read.
/// - no `"`: it would end the quoted value early.
/// - no `\`: an escape character in real TOML. Refused so the file stays
///   valid TOML and any other TOML tool reads the same value.
/// - no control bytes (0x00-0x1F, 0x7F): a newline would split the line;
///   the others cannot be seen or typed in a hand-edited file.
///
/// Non-ASCII UTF-8 is allowed; the reader copies it byte for byte.
fn is_storable_config_field_path_text(candidate_text: &str) -> bool {
    !candidate_text.is_empty()
        && candidate_text.len() <= MAX_CONFIG_PATH_BYTES
        && candidate_text
            .bytes()
            .all(|byte| byte != b'"' && byte != b'\\' && byte >= 0x20 && byte != 0x7F)
}

/// An absolute filesystem path stored as a field VALUE inside a config file
/// (`target_crate_path`, `modeling_data_path`).
///
/// Not the path OF a config file: that is an `AbsolutePath`, passed to
/// `write_new_config_file` and `load_config_file`.
///
/// # Project context
/// A config file is text, so this type stores the path as UTF-8 text that
/// satisfies `is_storable_config_field_path_text`. Any value of this type can
/// therefore be written to a config file and read back unchanged. Nothing is
/// opened or checked on disk: whether the path exists is checked by the step
/// that uses it (e.g. running cargo in the target crate).
///
/// One accessor, `get_path_str`, so the value has one name and one recheck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFieldPath {
    /// The path's own characters, e.g. `/home/user/code/Pumpkin`.
    field_path_text: String,
}

impl ConfigFieldPath {
    /// Validates and constructs.
    ///
    /// # Arguments
    /// - `candidate_path`: from the user (wizard), from the working directory,
    ///   or from a config file being loaded.
    ///
    /// # Returns
    /// - `Ok(ConfigFieldPath)`.
    /// - `Err(CfgPathValueInvalid)` (input validation): not UTF-8, empty,
    ///   longer than `MAX_CONFIG_PATH_BYTES`, or contains `"`, `\`, or a control byte.
    /// - `Err(CfgPathNotAbsolute)` (input validation).
    ///
    /// # Modes
    /// Debug builds print the rejected path. Production-release returns the code only.
    pub fn new(candidate_path: &Path) -> Result<Self, HeatmapError> {
        let candidate_text = match candidate_path.to_str() {
            Some(text) => text,
            None => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: config field path is not UTF-8: {}",
                    HeatmapError::CfgPathValueInvalid.code(),
                    candidate_path.display()
                );
                return Err(HeatmapError::CfgPathValueInvalid);
            }
        };

        // --- Check: path is absolute ---
        // input validation: paths come from the user or a hand-editable file.
        if !candidate_path.is_absolute() {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: config field path is not absolute: {:?}",
                HeatmapError::CfgPathNotAbsolute.code(),
                candidate_text
            );
            return Err(HeatmapError::CfgPathNotAbsolute);
        }

        // --- Check: path text can be stored and read back unchanged ---
        // input validation: see `is_storable_config_field_path_text`.
        if !is_storable_config_field_path_text(candidate_text) {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: config field path not storable ({} bytes, max {}; no \" \\ or control bytes): {:?}",
                HeatmapError::CfgPathValueInvalid.code(),
                candidate_text.len(),
                MAX_CONFIG_PATH_BYTES,
                candidate_text
            );
            return Err(HeatmapError::CfgPathValueInvalid);
        }

        Ok(Self {
            field_path_text: candidate_text.to_string(),
        })
    }

    /// Returns the stored path itself, as `&str`, after rechecking it.
    ///
    /// This returns the characters of the path (e.g. `/home/user/code/Pumpkin`),
    /// not the contents of any file: no file is opened or read. Callers that
    /// need a `&Path` wrap the result: `Path::new(field_path.get_path_str()?)`.
    ///
    /// # Returns
    /// - `Ok(&str)`.
    /// - `Err(CfgPathValueCorrupted)` (internal invariant): `new` checked the
    ///   same rules, so a failure means the stored value changed after
    ///   construction (e.g. memory corruption) or was built without `new`.
    ///
    /// # Modes
    /// Debug builds (not test) panic via `debug_assert!`; test and debug builds
    /// print; production-release returns the code only.
    pub fn get_path_str(&self) -> Result<&str, HeatmapError> {
        // --- Check: stored path still satisfies the construction rules ---
        // internal invariant: only `new` creates values, with these same checks.
        let is_intact = is_storable_config_field_path_text(&self.field_path_text)
            && Path::new(&self.field_path_text).is_absolute();
        if !is_intact {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: ConfigFieldPath corrupted",
                HeatmapError::CfgPathValueCorrupted.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: ConfigFieldPath recheck failed",
                HeatmapError::CfgPathValueCorrupted.code()
            );
            return Err(HeatmapError::CfgPathValueCorrupted);
        }
        Ok(self.field_path_text.as_str())
    }
}

// ----------------------------------------------------------------------------
// The config
// ----------------------------------------------------------------------------

/// Everything needed to repeat a run (one config file).
///
/// Every field is an enforced type, so a `HixConfig` that exists can always
/// be written and read back unchanged. New fields: add a key constant, add
/// it to `CONFIG_KEYS`, write it in `write_config_lines`, read it in
/// `load_config_file`, and consider raising `CONFIG_FORMAT_VERSION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HixConfig {
    /// Crate directory where cargo commands for the target run.
    target_crate_path: ConfigPath,
    /// Binary to run (`--bin`); required for workspaces with several binaries.
    target_binary_name: CargoBinaryName,
    /// Directory holding the `run_NNN_<scenario>` folders.
    modeling_data_path: ConfigPath,
    /// Scenario: names the run folders and this config file.
    scenario_name: ScenarioName,
    /// Purpose of the analysis made after each run (`analysis_NNN_<purpose>`).
    analysis_purpose: AnalysisPurpose,
    /// Rows per Top-N table in the report.
    top_n: TopNCount,
    /// Name of the work unit (e.g. `chunks_generated`); the count is per run.
    work_unit_name: Option<WorkUnitName>,
    /// Also write `rustfilt`-demangled copies of the report and TSV.
    demangle_outputs: bool,
}

/// Config file name for a scenario: `hix_<scenario>.toml`.
///
/// # Returns
/// - `Ok(file_name)`.
/// - `Err(TypeScenarioNameCorrupted)` from the name's recheck.
fn config_file_name_for_scenario(scenario_name: &ScenarioName) -> Result<String, HeatmapError> {
    let scenario_text = scenario_name.ntk_get()?;
    let name_length = CONFIG_FILE_NAME_PREFIX
        .len()
        .saturating_add(scenario_text.len())
        .saturating_add(CONFIG_FILE_NAME_SUFFIX.len());
    let mut file_name = String::with_capacity(name_length);
    file_name.push_str(CONFIG_FILE_NAME_PREFIX);
    file_name.push_str(scenario_text);
    file_name.push_str(CONFIG_FILE_NAME_SUFFIX);
    Ok(file_name)
}

// ----------------------------------------------------------------------------
// Writing
// ----------------------------------------------------------------------------

/// Maps a failed write into the render buffer to its code.
///
/// Internal invariant: `CONFIG_FILE_MAX_BYTES` holds a config with every field
/// at its maximum (checked by test), so this happens only with a smaller
/// buffer (tests) or after a key or field was added without raising the size.
fn config_render_error(_io_error: std::io::Error) -> HeatmapError {
    #[cfg(all(debug_assertions, not(test)))]
    debug_assert!(
        false,
        "HIX-{}: config render buffer full: {}",
        HeatmapError::CfgRenderBufferFull.code(),
        _io_error
    );
    #[cfg(debug_assertions)]
    eprintln!(
        "HIX-{}: config render buffer full: {}",
        HeatmapError::CfgRenderBufferFull.code(),
        _io_error
    );
    HeatmapError::CfgRenderBufferFull
}

/// Writes the config file lines (the layout in the section comment above).
///
/// # Returns
/// - `Ok(())`.
/// - `Err(CfgRenderBufferFull)` from `config_render_error`.
/// - `Err` from a field's recheck (`CfgPathValueCorrupted`, `Type*Corrupted`).
fn write_config_lines<W: Write>(
    config_writer: &mut W,
    config: &HixConfig,
) -> Result<(), HeatmapError> {
    writeln!(
        config_writer,
        "# HIX config file (TOML subset: one `key = value` per line, top level only)."
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "# Written by HIX. Hand edits are allowed; values may not contain double quotes or backslashes."
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "{} = {}",
        CONFIG_KEY_FORMAT_VERSION, CONFIG_FORMAT_VERSION
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "{} = \"{}\"",
        CONFIG_KEY_TARGET_CRATE_PATH,
        config.target_crate_path.cp_get_text()?
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "{} = \"{}\"",
        CONFIG_KEY_TARGET_BINARY_NAME,
        config.target_binary_name.ntk_get()?
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "{} = \"{}\"",
        CONFIG_KEY_MODELING_DATA_PATH,
        config.modeling_data_path.cp_get_text()?
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "{} = \"{}\"",
        CONFIG_KEY_SCENARIO_NAME,
        config.scenario_name.ntk_get()?
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "{} = \"{}\"",
        CONFIG_KEY_ANALYSIS_PURPOSE,
        config.analysis_purpose.ntk_get()?
    )
    .map_err(config_render_error)?;
    writeln!(
        config_writer,
        "{} = {}",
        CONFIG_KEY_TOP_N,
        config.top_n.tnc_get()?
    )
    .map_err(config_render_error)?;
    if let Some(work_unit_name) = &config.work_unit_name {
        writeln!(
            config_writer,
            "{} = \"{}\"",
            CONFIG_KEY_WORK_UNIT_NAME,
            work_unit_name.wun_get()?
        )
        .map_err(config_render_error)?;
    }
    writeln!(
        config_writer,
        "{} = {}",
        CONFIG_KEY_DEMANGLE_OUTPUTS, config.demangle_outputs
    )
    .map_err(config_render_error)?;
    Ok(())
}

/// Renders the config file text into `output_buffer` (no heap) and returns
/// the written part.
///
/// # Project context
/// The whole file is formatted in memory before the file is created, so a
/// failure never leaves a half-written config on disk (HIX never deletes).
/// The caller (`write_new_config_file`) passes a `CONFIG_FILE_MAX_BYTES`
/// stack array; tests also pass smaller buffers.
///
/// # Returns
/// - `Ok(rendered_bytes)`: the start of `output_buffer` holding the file text.
/// - `Err(CfgRenderBufferFull)` (from `config_render_error`): the text does not fit.
/// - `Err(CfgRenderedRangeInvalid)` (internal invariant): the writer's end
///   position does not describe a range inside the buffer.
/// - `Err` from a field's recheck (`CfgPathValueCorrupted`, `Type*Corrupted`).
///
/// # Modes
/// The internal-invariant check panics in debug builds (not test); test and
/// debug builds print; production-release returns the code only.
fn render_config_file_text<'buffer>(
    config: &HixConfig,
    output_buffer: &'buffer mut [u8],
) -> Result<&'buffer [u8], HeatmapError> {
    let mut buffer_writer = std::io::Cursor::new(output_buffer);
    write_config_lines(&mut buffer_writer, config)?;
    let written_end_position = buffer_writer.position();
    let full_buffer: &'buffer [u8] = buffer_writer.into_inner();

    // --- Check: the written end position is a range inside the buffer ---
    // internal invariant: a Cursor never writes past its buffer, so its
    // position is at most the buffer length, which fits in usize.
    let rendered_bytes = match usize::try_from(written_end_position) {
        Ok(written_length) => full_buffer.get(..written_length),
        Err(_conversion_error) => None,
    };
    match rendered_bytes {
        Some(bytes) => Ok(bytes),
        None => {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: rendered end {} outside buffer of {} bytes",
                HeatmapError::CfgRenderedRangeInvalid.code(),
                written_end_position,
                full_buffer.len()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: rendered end {} outside buffer of {} bytes",
                HeatmapError::CfgRenderedRangeInvalid.code(),
                written_end_position,
                full_buffer.len()
            );
            Err(HeatmapError::CfgRenderedRangeInvalid)
        }
    }
}

/// Writes a new config file, then reads it back and compares.
///
/// # Project context
/// Config files are a permanent record of how runs were made, like run and
/// analysis folders, so an existing file is never overwritten. The reader
/// defines the file format; the writer is checked against the reader rather
/// than trusted: the file is read back with the same no-heap reader that the
/// wizard and replay use, and compared with what was meant.
///
/// # Steps
/// 1. Render the whole text into a stack buffer (nothing on disk yet).
/// 2. Create the file (create-new; Tier-1 retry for transient errors),
///    write it in one `write_all`, and sync it to disk.
/// 3. Load it with `load_config_file` and compare with `config`.
///
/// If step 2 or 3 fails after the file was created, the file stays in place
/// (HIX never deletes); the returned code says not to use it.
///
/// # Arguments
/// - `config_file_path`: absolute path of the config file to create; its
///   directory must already exist.
/// - `config`: the config to write.
///
/// # Returns
/// - `Ok(())`.
/// - `Err(821 | 822 | 823 | 824 | 825)`: creating the file failed
///   (824: the file exists; it is not overwritten).
/// - `Err(CfgWriteFailed | CfgSyncFailed)`.
/// - `Err(CfgRoundTripMismatch)` (internal invariant).
/// - `Err` from `render_config_file_text` and `load_config_file`.
///
/// # Modes
/// Debug builds print each failure; the round-trip check also panics in
/// debug builds (not test). Production-release returns the code only.
pub fn write_new_config_file(
    config_file_path: &AbsolutePath,
    config: &HixConfig,
) -> Result<(), HeatmapError> {
    let file_path = config_file_path.ap_get()?;

    let mut render_buffer: [u8; CONFIG_FILE_MAX_BYTES] = [0u8; CONFIG_FILE_MAX_BYTES];
    let rendered_bytes = render_config_file_text(config, &mut render_buffer)?;

    let mut config_file = open_file_with_retry(
        file_path,
        FileOpenPurpose::CreateNew,
        CONFIG_WRITE_OPEN_ERROR_CODES,
    )?;
    if let Err(_io_error) = config_file.write_all(rendered_bytes) {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: config write failed: {}",
            HeatmapError::CfgWriteFailed.code(),
            _io_error
        );
        return Err(HeatmapError::CfgWriteFailed);
    }
    if let Err(_io_error) = config_file.sync_all() {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: config sync failed: {}",
            HeatmapError::CfgSyncFailed.code(),
            _io_error
        );
        return Err(HeatmapError::CfgSyncFailed);
    }
    // Release the file handle before reading the file back.
    drop(config_file);

    // --- Check: the file reads back as exactly the config written ---
    // internal invariant: the writer and the loader implement the same layout.
    let reloaded_config = load_config_file(config_file_path)?;
    if reloaded_config != *config {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert!(
            false,
            "HIX-{}: config read-back differs",
            HeatmapError::CfgRoundTripMismatch.code()
        );
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: config read-back differs: wrote {:?}, read {:?}",
            HeatmapError::CfgRoundTripMismatch.code(),
            config,
            reloaded_config
        );
        return Err(HeatmapError::CfgRoundTripMismatch);
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Reading
// ----------------------------------------------------------------------------

/// Reads one config value into a `VALUE_BUFFER_BYTES` stack array, checks
/// that it is UTF-8, and hands it to `parse_value`.
///
/// # Returns
/// - `Ok(T)` from `parse_value`.
/// - Errors from the field reader (e.g. 811 missing, 812 too long).
/// - `Err(CfgValueLengthInvalid)` (internal invariant: the reader's length
///   is within its buffer).
/// - `Err(CfgValueNotUtf8)` (input validation).
/// - Errors from `parse_value`.
fn read_config_value<T, F, const VALUE_BUFFER_BYTES: usize>(
    config_file_path: &Path,
    config_key: &str,
    parse_value: F,
) -> Result<T, HeatmapError>
where
    F: FnOnce(&str) -> Result<T, HeatmapError>,
{
    let (value_buffer, value_length) = read_single_line_field_from_toml_no_heap::<
        VALUE_BUFFER_BYTES,
    >(config_file_path, config_key)?;
    let value_bytes = match value_buffer.get(..value_length) {
        Some(bytes) => bytes,
        None => {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: value length {} beyond buffer {}",
                HeatmapError::CfgValueLengthInvalid.code(),
                value_length,
                VALUE_BUFFER_BYTES
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: value length {} beyond buffer {}",
                HeatmapError::CfgValueLengthInvalid.code(),
                value_length,
                VALUE_BUFFER_BYTES
            );
            return Err(HeatmapError::CfgValueLengthInvalid);
        }
    };
    let value_text = match std::str::from_utf8(value_bytes) {
        Ok(text) => text,
        Err(_utf8_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: value of {:?} is not UTF-8: {}",
                HeatmapError::CfgValueNotUtf8.code(),
                config_key,
                _utf8_error
            );
            return Err(HeatmapError::CfgValueNotUtf8);
        }
    };
    parse_value(value_text)
}

/// Checks `hix_config_version`.
/// `Err(CfgVersionNotANumber | CfgUnsupportedVersion)` (input validation).
fn check_config_format_version(value_text: &str) -> Result<(), HeatmapError> {
    let format_version = match value_text.trim().parse::<u32>() {
        Ok(version) => version,
        Err(_parse_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: hix_config_version {:?}: {}",
                HeatmapError::CfgVersionNotANumber.code(),
                value_text,
                _parse_error
            );
            return Err(HeatmapError::CfgVersionNotANumber);
        }
    };
    if format_version != CONFIG_FORMAT_VERSION {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: hix_config_version {} (this HIX reads {})",
            HeatmapError::CfgUnsupportedVersion.code(),
            format_version,
            CONFIG_FORMAT_VERSION
        );
        return Err(HeatmapError::CfgUnsupportedVersion);
    }
    Ok(())
}

/// Parses a path value. Errors: see `ConfigPath::new`.
fn parse_config_path(value_text: &str) -> Result<ConfigPath, HeatmapError> {
    ConfigPath::cp_new(Path::new(value_text))
}

/// Parses `top_n`. `Err(CfgTopNInvalid)` (input validation): not a number
/// or outside 1..=`MAX_TOP_N`. A config-specific code, so a bad config is not
/// reported as a command-line mistake.
fn parse_config_top_n(value_text: &str) -> Result<TopNCount, HeatmapError> {
    let top_n_value = match value_text.trim().parse::<u16>() {
        Ok(value) => value,
        Err(_parse_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: top_n {:?}: {}",
                HeatmapError::CfgTopNInvalid.code(),
                value_text,
                _parse_error
            );
            return Err(HeatmapError::CfgTopNInvalid);
        }
    };
    match TopNCount::tnc_new(top_n_value) {
        Ok(top_n) => Ok(top_n),
        Err(_type_error) => Err(HeatmapError::CfgTopNInvalid),
    }
}

/// Parses a boolean: exactly `true` or `false` (spaces around allowed).
/// `Err(CfgBooleanInvalid)` (input validation).
fn parse_config_boolean(value_text: &str) -> Result<bool, HeatmapError> {
    match value_text.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: boolean {:?} is not true or false",
                HeatmapError::CfgBooleanInvalid.code(),
                value_text
            );
            Err(HeatmapError::CfgBooleanInvalid)
        }
    }
}

/// Parses `work_unit_name`. `Err(CfgWorkUnitNameInvalid)` (input validation);
/// a config-specific code, so a bad config is not reported as a command-line mistake.
fn parse_config_work_unit_name(value_text: &str) -> Result<WorkUnitName, HeatmapError> {
    match WorkUnitName::wun_new(value_text) {
        Ok(work_unit_name) => Ok(work_unit_name),
        Err(_type_error) => Err(HeatmapError::CfgWorkUnitNameInvalid),
    }
}

/// Loads and validates a config file.
///
/// # Steps
/// 1. Refuse duplicate keys (816), so no value is silently ignored.
/// 2. Require `hix_config_version` == `CONFIG_FORMAT_VERSION`.
/// 3. Read each field into a stack buffer and build its enforced type.
///    `work_unit_name` is optional (missing = `None`); all others are required.
///
/// Cost: about two file opens per key, each read one byte per read call.
/// Negligible for a file of about a dozen lines.
///
/// # Returns
/// - `Ok(HixConfig)`.
/// - `Err`: field-reader codes 801-816 (811: a required key is missing;
///   812: a value is longer than its buffer); 817-818 (paths);
///   829-835; 164/166/168 (names); 155 (the file path's own recheck).
pub fn load_config_file(config_file_path: &AbsolutePath) -> Result<HixConfig, HeatmapError> {
    let file_path = config_file_path.ap_get()?;
    check_toml_keys_are_unique_no_heap(file_path, &CONFIG_KEYS)?;

    read_config_value::<_, _, CONFIG_SHORT_VALUE_BUFFER_BYTES>(
        file_path,
        CONFIG_KEY_FORMAT_VERSION,
        check_config_format_version,
    )?;

    let target_crate_path = read_config_value::<_, _, MAX_CONFIG_PATH_BYTES>(
        file_path,
        CONFIG_KEY_TARGET_CRATE_PATH,
        parse_config_path,
    )?;
    let target_binary_name = read_config_value::<_, _, CONFIG_SHORT_VALUE_BUFFER_BYTES>(
        file_path,
        CONFIG_KEY_TARGET_BINARY_NAME,
        CargoBinaryName::ntk_new,
    )?;
    let modeling_data_path = read_config_value::<_, _, MAX_CONFIG_PATH_BYTES>(
        file_path,
        CONFIG_KEY_MODELING_DATA_PATH,
        parse_config_path,
    )?;
    let scenario_name = read_config_value::<_, _, CONFIG_SHORT_VALUE_BUFFER_BYTES>(
        file_path,
        CONFIG_KEY_SCENARIO_NAME,
        ScenarioName::ntk_new,
    )?;
    let analysis_purpose = read_config_value::<_, _, CONFIG_SHORT_VALUE_BUFFER_BYTES>(
        file_path,
        CONFIG_KEY_ANALYSIS_PURPOSE,
        AnalysisPurpose::ntk_new,
    )?;
    let top_n = read_config_value::<_, _, CONFIG_SHORT_VALUE_BUFFER_BYTES>(
        file_path,
        CONFIG_KEY_TOP_N,
        parse_config_top_n,
    )?;
    let work_unit_name = match read_config_value::<_, _, CONFIG_SHORT_VALUE_BUFFER_BYTES>(
        file_path,
        CONFIG_KEY_WORK_UNIT_NAME,
        parse_config_work_unit_name,
    ) {
        Ok(work_unit_name) => Some(work_unit_name),
        // Optional field: absent means "not set".
        Err(HeatmapError::RSLFFieldNotFound) => None,
        Err(other_error) => return Err(other_error),
    };
    let demangle_outputs = read_config_value::<_, _, CONFIG_SHORT_VALUE_BUFFER_BYTES>(
        file_path,
        CONFIG_KEY_DEMANGLE_OUTPUTS,
        parse_config_boolean,
    )?;

    Ok(HixConfig {
        target_crate_path,
        target_binary_name,
        modeling_data_path,
        scenario_name,
        analysis_purpose,
        top_n,
        work_unit_name,
        demangle_outputs,
    })
}

// end TOML section

// ============================================================================
// Enforced custom types (value integrity)
// ============================================================================

/// Number of rows per Top-N table. Valid range: 1..=MAX_TOP_N.
/// Field is private: construct only through `new`, read only through `get`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopNCount {
    top_n_value: u16,
}

impl TopNCount {
    /// Validates and constructs. Input-validation error (user-facing).
    pub fn tnc_new(candidate_top_n: u16) -> Result<Self, HeatmapError> {
        if candidate_top_n == 0 || candidate_top_n > MAX_TOP_N {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: top-n {} outside 1..={}",
                HeatmapError::TypeTopNOutOfRange.code(),
                candidate_top_n,
                MAX_TOP_N
            );
            return Err(HeatmapError::TypeTopNOutOfRange);
        }
        Ok(Self {
            top_n_value: candidate_top_n,
        })
    }

    /// Returns the value after re-checking validity (guards corruption).
    pub fn tnc_get(&self) -> Result<u16, HeatmapError> {
        if self.top_n_value == 0 || self.top_n_value > MAX_TOP_N {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: TopNCount corrupted: {}",
                HeatmapError::TypeTopNCorrupted.code(),
                self.top_n_value
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: TopNCount recheck failed: {}",
                HeatmapError::TypeTopNCorrupted.code(),
                self.top_n_value
            );
            return Err(HeatmapError::TypeTopNCorrupted);
        }
        Ok(self.top_n_value)
    }
}

/// 1-based source line number (LCOV and editors are 1-based; 0 is invalid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceLineNumber {
    line_value: u32,
}

impl SourceLineNumber {
    /// Validates and constructs (line >= 1).
    pub fn sln_new(candidate_line: u32) -> Result<Self, HeatmapError> {
        if candidate_line == 0 {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: line number 0 is invalid",
                HeatmapError::TypeLineNumberZero.code()
            );
            return Err(HeatmapError::TypeLineNumberZero);
        }
        Ok(Self {
            line_value: candidate_line,
        })
    }

    /// Returns the value after re-checking validity.
    pub fn sln_get(&self) -> Result<u32, HeatmapError> {
        if self.line_value == 0 {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: SourceLineNumber corrupted: 0",
                HeatmapError::TypeLineNumberCorrupted.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: SourceLineNumber recheck failed",
                HeatmapError::TypeLineNumberCorrupted.code()
            );
            return Err(HeatmapError::TypeLineNumberCorrupted);
        }
        Ok(self.line_value)
    }
}

/// A path guaranteed (and re-checked) to be absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsolutePath {
    absolute_path: PathBuf,
}

impl AbsolutePath {
    /// Validates and constructs (path must be absolute).
    pub fn ap_new(candidate_path: PathBuf) -> Result<Self, HeatmapError> {
        if !candidate_path.is_absolute() {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: not absolute: {}",
                HeatmapError::TypePathNotAbsolute.code(),
                candidate_path.display()
            );
            return Err(HeatmapError::TypePathNotAbsolute);
        }
        Ok(Self {
            absolute_path: candidate_path,
        })
    }

    /// Returns the path after re-checking validity.
    pub fn ap_get(&self) -> Result<&Path, HeatmapError> {
        if !self.absolute_path.is_absolute() {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: AbsolutePath corrupted",
                HeatmapError::TypePathCorrupted.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: AbsolutePath recheck failed",
                HeatmapError::TypePathCorrupted.code()
            );
            return Err(HeatmapError::TypePathCorrupted);
        }
        Ok(self.absolute_path.as_path())
    }
}

/// True if `candidate_text` is 1..=`max_bytes` ASCII letters, digits, `_`, `-`, `.`.
///
/// Shared rule for run-metadata text (`RunLabel`, `WorkUnitName`): safe to
/// print in the report, safe as a TSV field (no tabs or newlines), and safe
/// as part of a folder name (no `/`, no spaces).
fn is_valid_metadata_text(candidate_text: &str, max_bytes: usize) -> bool {
    !candidate_text.is_empty()
        && candidate_text.len() <= max_bytes
        && candidate_text.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        })
}

/// Run label, e.g. `run_005_pumpkin_world_spawn_only`. See `is_valid_metadata_text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLabel {
    run_label_text: String,
}

impl RunLabel {
    /// Validates and constructs. Input-validation error (user-facing).
    pub fn rl_new(candidate_text: &str) -> Result<Self, HeatmapError> {
        if !is_valid_metadata_text(candidate_text, MAX_RUN_LABEL_BYTES) {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: invalid --run-label {:?} (1..={} of A-Z a-z 0-9 _ - .)",
                HeatmapError::TypeRunLabelInvalid.code(),
                candidate_text,
                MAX_RUN_LABEL_BYTES
            );
            return Err(HeatmapError::TypeRunLabelInvalid);
        }
        Ok(Self {
            run_label_text: candidate_text.to_string(),
        })
    }

    /// Returns the label after re-checking validity (guards corruption).
    pub fn rl_get(&self) -> Result<&str, HeatmapError> {
        if !is_valid_metadata_text(&self.run_label_text, MAX_RUN_LABEL_BYTES) {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: RunLabel corrupted",
                HeatmapError::TypeRunLabelCorrupted.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: RunLabel recheck failed",
                HeatmapError::TypeRunLabelCorrupted.code()
            );
            return Err(HeatmapError::TypeRunLabelCorrupted);
        }
        Ok(self.run_label_text.as_str())
    }
}

/// Seconds the instrumented program ran. Valid range: 1..=MAX_RUN_DURATION_SECS.
/// Never 0, so "per minute" figures cannot divide by zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunDurationSeconds {
    duration_seconds: u64,
}

impl RunDurationSeconds {
    /// Validates and constructs. Input-validation error (user-facing).
    pub fn rds_new(candidate_seconds: u64) -> Result<Self, HeatmapError> {
        if candidate_seconds == 0 || candidate_seconds > MAX_RUN_DURATION_SECS {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: run duration {} outside 1..={}",
                HeatmapError::TypeRunDurationOutOfRange.code(),
                candidate_seconds,
                MAX_RUN_DURATION_SECS
            );
            return Err(HeatmapError::TypeRunDurationOutOfRange);
        }
        Ok(Self {
            duration_seconds: candidate_seconds,
        })
    }

    /// Returns the value after re-checking validity.
    pub fn rds_get(&self) -> Result<u64, HeatmapError> {
        if self.duration_seconds == 0 || self.duration_seconds > MAX_RUN_DURATION_SECS {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: RunDurationSeconds corrupted: {}",
                HeatmapError::TypeRunDurationCorrupted.code(),
                self.duration_seconds
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: RunDurationSeconds recheck failed: {}",
                HeatmapError::TypeRunDurationCorrupted.code(),
                self.duration_seconds
            );
            return Err(HeatmapError::TypeRunDurationCorrupted);
        }
        Ok(self.duration_seconds)
    }
}

/// Work done during the run. Valid range: 1..=MAX_WORK_UNITS.
/// Never 0, so "per work unit" figures cannot divide by zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkUnitCount {
    work_unit_count: u64,
}

impl WorkUnitCount {
    /// Validates and constructs. Input-validation error (user-facing).
    pub fn wuc_new(candidate_count: u64) -> Result<Self, HeatmapError> {
        if candidate_count == 0 || candidate_count > MAX_WORK_UNITS {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: work units {} outside 1..={}",
                HeatmapError::TypeWorkUnitsOutOfRange.code(),
                candidate_count,
                MAX_WORK_UNITS
            );
            return Err(HeatmapError::TypeWorkUnitsOutOfRange);
        }
        Ok(Self {
            work_unit_count: candidate_count,
        })
    }

    /// Returns the value after re-checking validity.
    pub fn wuc_get(&self) -> Result<u64, HeatmapError> {
        if self.work_unit_count == 0 || self.work_unit_count > MAX_WORK_UNITS {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: WorkUnitCount corrupted: {}",
                HeatmapError::TypeWorkUnitsCorrupted.code(),
                self.work_unit_count
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: WorkUnitCount recheck failed: {}",
                HeatmapError::TypeWorkUnitsCorrupted.code(),
                self.work_unit_count
            );
            return Err(HeatmapError::TypeWorkUnitsCorrupted);
        }
        Ok(self.work_unit_count)
    }
}

/// Name of the work unit, e.g. `chunks_generated`. See `is_valid_metadata_text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkUnitName {
    work_unit_name_text: String,
}

impl WorkUnitName {
    /// Validates and constructs. Input-validation error (user-facing).
    pub fn wun_new(candidate_text: &str) -> Result<Self, HeatmapError> {
        if !is_valid_metadata_text(candidate_text, MAX_WORK_UNIT_NAME_BYTES) {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: invalid --work-unit-name {:?} (1..={} of A-Z a-z 0-9 _ - .)",
                HeatmapError::TypeWorkUnitNameInvalid.code(),
                candidate_text,
                MAX_WORK_UNIT_NAME_BYTES
            );
            return Err(HeatmapError::TypeWorkUnitNameInvalid);
        }
        Ok(Self {
            work_unit_name_text: candidate_text.to_string(),
        })
    }

    /// Returns the name after re-checking validity (guards corruption).
    pub fn wun_get(&self) -> Result<&str, HeatmapError> {
        if !is_valid_metadata_text(&self.work_unit_name_text, MAX_WORK_UNIT_NAME_BYTES) {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: WorkUnitName corrupted",
                HeatmapError::TypeWorkUnitNameCorrupted.code()
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: WorkUnitName recheck failed",
                HeatmapError::TypeWorkUnitNameCorrupted.code()
            );
            return Err(HeatmapError::TypeWorkUnitNameCorrupted);
        }
        Ok(self.work_unit_name_text.as_str())
    }
}

/// Work done in the run: count and unit name, always together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkUnits {
    count: WorkUnitCount,
    name: WorkUnitName,
}

/// Optional description of the run that produced the LCOV.
/// Every field is optional; absent fields print as `(not given)`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunMetadata {
    run_label: Option<RunLabel>,
    run_duration: Option<RunDurationSeconds>,
    work_units: Option<WorkUnits>,
}

/// Validated run configuration produced from the command line.
pub struct HeatmapRunConfiguration {
    lcov_input_path: AbsolutePath,
    output_directory_path: AbsolutePath,
    top_n: TopNCount,
    run_metadata: RunMetadata,
}

// ============================================================================
// Internal data model
// ============================================================================

/// Coverage data for one `SF:` ... `end_of_record` block (one source file).
#[derive(Debug)]
struct FileCoverageRecord {
    /// Source path exactly as written in LCOV (normally absolute with cargo llvm-cov).
    source_path_text: String,
    /// `FN:<line>,<name>` entries, in file order.
    function_definitions: Vec<(SourceLineNumber, String)>,
    /// `FNDA:<count>,<name>` entries, summed per name.
    function_entry_counts: HashMap<String, u64>,
    /// `DA:<line>,<count>` entries (max kept if a line repeats).
    line_execution_counts: HashMap<SourceLineNumber, u64>,
    /// Max of all `DA` counts in this file: 0 means the whole file is cold.
    max_line_execution_count: u64,
}

impl FileCoverageRecord {
    fn new(source_path_text: &str) -> Self {
        Self {
            source_path_text: source_path_text.to_string(),
            function_definitions: Vec::new(),
            function_entry_counts: HashMap::new(),
            line_execution_counts: HashMap::new(),
            max_line_execution_count: 0,
        }
    }
}

/// One ranked heat site (a function or a loop header) identified by file + line.
#[derive(Debug, Clone)]
struct HeatSite {
    /// Index into the `FileCoverageRecord` slice (resolves to the source path).
    source_file_index: usize,
    /// 1-based line of the function definition or loop header.
    line_number: SourceLineNumber,
    /// Function name (possibly mangled) or "for loop in <function>".
    display_name: String,
    /// Function: entry count (calls). Loop: header-line count (≈ iterations).
    execution_count: u64,
    /// Number of LCOV function instances merged into this site (generics).
    merged_instance_count: u32,
    /// Loops only: summed entry count (all instances) of the enclosing
    /// function's definition line. `None` for function sites, or when no
    /// enclosing function was found. Basis of the derived ratio
    /// "loop header executions per call of the enclosing function".
    enclosing_function_entry_count: Option<u64>,
}

/// Which loop keyword began a detected loop header line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopKeyword {
    For,
    While,
    Loop,
}

impl LoopKeyword {
    fn as_label(self) -> &'static str {
        match self {
            LoopKeyword::For => "for",
            LoopKeyword::While => "while",
            LoopKeyword::Loop => "loop",
        }
    }
}

/// Transparency counters for the loop scan (reported in the
/// `[loop-scan coverage]` block of the text report).
///
/// Every source file listed in the LCOV is counted exactly once: either as
/// scanned, or under exactly one skip reason. No file is silently unexplained.
#[derive(Debug, Default, Clone, Copy)]
struct LoopScanStatistics {
    /// Source files listed in the LCOV.
    files_total: usize,
    /// Files read to the end and searched for loop headers.
    files_scanned: usize,
    /// Files skipped because every line count is 0 (cannot contain a hot loop).
    files_skipped_cold: usize,
    /// Files skipped because the LCOV path is not absolute.
    files_skipped_non_absolute_path: usize,
    /// Files skipped because they no longer exist at the LCOV path.
    files_skipped_not_found: usize,
    /// Files skipped because they could not be opened (permissions).
    files_skipped_permission_denied: usize,
    /// Files abandoned because one line's discarded remainder exceeded
    /// `MAX_SKIPPED_LINE_BYTES`.
    files_skipped_line_exceeds_skip_cap: usize,
    /// Files abandoned because they exceed `MAX_SOURCE_LINES_PER_FILE`.
    files_skipped_too_many_lines: usize,
    /// Files abandoned for any other reason (read failures and similar).
    files_skipped_other_error: usize,
    /// Scanned files that contain at least one over-long line.
    files_with_overlong_source_lines: usize,
    /// Over-long lines across all scanned files (start scanned, rest discarded).
    overlong_source_lines_total: usize,
    /// Loop headers found by the lexical scan, with or without a line count.
    loop_headers_found: usize,
    /// Loop headers whose line has no LCOV `DA` count (not instrumented,
    /// compiled out, or a lexical false positive).
    loop_headers_without_line_data: usize,
}

/// Why a non-cold source file was not scanned for loops (exactly one reason per file).
///
/// # Project context
/// Single source of truth for skip classification: the counters in
/// `LoopScanStatistics` and the `[loop-scan file notes]` listing both use
/// `from_scan_error`, so the counted and the listed reasons cannot disagree.
/// Cold files are not a skip reason here: they are counted only, never listed.
///
/// Variant order is the listing order in the report (derives `Ord`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FileSkipReason {
    NonAbsolutePath,
    NotFound,
    PermissionDenied,
    LineExceedsSkipCap,
    TooManyLines,
    OtherError,
}

impl FileSkipReason {
    /// Classifies the error that stopped one file's scan.
    /// Codes without their own reason are "other error"; the listing still
    /// shows the exact code, so nothing is hidden.
    fn from_scan_error(scan_error: HeatmapError) -> Self {
        match scan_error {
            HeatmapError::TypePathNotAbsolute => FileSkipReason::NonAbsolutePath,
            HeatmapError::SrcOpenNotFound => FileSkipReason::NotFound,
            HeatmapError::SrcOpenPermissionDenied => FileSkipReason::PermissionDenied,
            HeatmapError::SrcLineExceedsSkipCap => FileSkipReason::LineExceedsSkipCap,
            HeatmapError::SrcTooManyLines => FileSkipReason::TooManyLines,
            _ => FileSkipReason::OtherError,
        }
    }

    /// Report label; matches the `[loop-scan coverage]` counter wording.
    fn as_label(self) -> &'static str {
        match self {
            FileSkipReason::NonAbsolutePath => "path not absolute",
            FileSkipReason::NotFound => "not found",
            FileSkipReason::PermissionDenied => "permission denied",
            FileSkipReason::LineExceedsSkipCap => "line > MAX_SKIPPED_LINE_BYTES",
            FileSkipReason::TooManyLines => "too many lines",
            FileSkipReason::OtherError => "other error",
        }
    }
}

/// One non-cold source file that was not scanned (its loops are missing).
#[derive(Debug, Clone, Copy)]
struct SkippedFileNote {
    /// Index into the `FileCoverageRecord` slice (resolves to the source path).
    source_file_index: usize,
    reason: FileSkipReason,
    /// Numeric code of the error that stopped the scan (from `HeatmapError::code()`).
    error_code: u16,
}

/// One scanned source file that had over-long lines (start of each scanned, rest skipped).
#[derive(Debug, Clone, Copy)]
struct PartlyScannedFileNote {
    /// Index into the `FileCoverageRecord` slice (resolves to the source path).
    source_file_index: usize,
    /// Number of lines longer than `MAX_LINE_BYTES` in this file.
    overlong_line_count: usize,
}

/// Per-file details behind the `[loop-scan coverage]` counters.
///
/// Bounded: at most one entry per LCOV source file (`MAX_SOURCE_FILES`).
/// Sorted by `scan_all_files_for_loops`:
/// - skipped files by reason, then LCOV file order;
/// - partly scanned files by over-long-line count (descending), then LCOV file order.
#[derive(Debug, Default)]
struct LoopScanFileNotes {
    skipped_files: Vec<SkippedFileNote>,
    partly_scanned_files: Vec<PartlyScannedFileNote>,
}

/// Result of scanning one source file.
#[derive(Debug, Default)]
struct SourceScanOutcome {
    /// Loop sites found in this file (only headers with a line count).
    loop_sites: Vec<HeatSite>,
    /// Loop headers found, with or without a line count.
    loop_headers_found: usize,
    /// Loop headers whose line has no LCOV `DA` count.
    loop_headers_without_line_data: usize,
    /// Lines longer than `MAX_LINE_BYTES` in this file (start scanned, rest discarded).
    overlong_lines_found: usize,
}

/// What `read_source_line_skipping_overlong` found when reading one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceLineReadOutcome {
    /// No more lines: the file has been read to the end.
    EndOfInput,
    /// A whole line (at most `MAX_LINE_BYTES` bytes) is in the line buffer.
    CompleteLine,
    /// The line was longer than `MAX_LINE_BYTES`. The line buffer holds its
    /// first `MAX_LINE_BYTES + 1` bytes; the rest has been read and discarded.
    OverLongLineStartKept {
        /// True if a block-comment end `*/` occurred in the discarded part,
        /// including a `*/` split between the kept start and the discarded part.
        discarded_part_contains_block_comment_end: bool,
    },
}

/// Summary statistics for one kind of site (functions or loops).
#[derive(Debug, Clone, Copy)]
struct HeatKindSummary {
    site_count: usize,
    zero_count_sites: usize,
    total_count: u128,
    /// Aligned with `CONCENTRATION_TARGETS_PERCENT`; 0 means "n/a" (total = 0).
    sites_reaching_percent: [usize; CONCENTRATION_TARGET_COUNT],
    decade_histogram: [u64; DECADE_BUCKET_COUNT],
}

/// Descriptive shape figures for one kind of site (functions or loops).
///
/// Experimental and descriptive: these figures summarize how counts are
/// spread across sites, so that runs and programs can be compared. They do
/// not by themselves indicate a problem. All `Option` figures are `None`
/// when the kind's total count is 0.
#[derive(Debug, Clone, Copy)]
struct DistributionShape {
    /// Gini over all sites (0 = all equal, 1 = one site has every count).
    gini_all_sites: Option<f64>,
    /// Gini over sites with count > 0 (spread among code that ran).
    gini_counted_sites: Option<f64>,
    /// Percent of all counts in the hottest `TOP_SHARE_NARROW_SITES` sites.
    top_narrow_share_percent: Option<f64>,
    /// Percent of all counts in the hottest `TOP_SHARE_WIDE_SITES` sites.
    top_wide_share_percent: Option<f64>,
    /// Largest run of empty decade buckets between occupied ones; `None` = no gap.
    largest_empty_decade_gap: Option<EmptyDecadeGap>,
    /// Largest adjacent-rank count ratio within the head; `None` = no drop.
    largest_head_drop: Option<HeadRankDrop>,
}

/// Empty orders of magnitude between two occupied decade buckets.
/// Bucket d (1..=20) holds counts in [10^(d-1), 10^d) (see `DECADE_BUCKET_COUNT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EmptyDecadeGap {
    /// Number of consecutive empty buckets.
    empty_decade_count: usize,
    /// Occupied bucket just below the gap.
    lower_bucket_index: usize,
    /// Occupied bucket just above the gap.
    upper_bucket_index: usize,
}

/// The largest count ratio between adjacent ranks within the head.
#[derive(Debug, Clone, Copy)]
struct HeadRankDrop {
    /// 0-based position of the higher site; the lower site is the next position.
    higher_position: usize,
    /// higher count / lower count (> 1.0).
    drop_ratio: f64,
}

/// Which way to open a file.
#[derive(Debug, Clone, Copy)]
enum FileOpenPurpose {
    ReadExisting,
    /// Create a file that must not exist yet (never truncates: no overwrite).
    CreateNew,
}

/// Per-call-site error codes for file opening, so each site keeps unique codes.
///
/// No `Debug` derive: the fields are `HeatmapError` values, which have no
/// `Debug` in production-release builds (no variant-name strings ship).
#[derive(Clone, Copy)]
struct OpenErrorCodes {
    not_found: HeatmapError,
    permission_denied: HeatmapError,
    transient: HeatmapError,
    /// `AlreadyExists`: only possible for `FileOpenPurpose::CreateNew`.
    already_exists: HeatmapError,
    other: HeatmapError,
}

const LCOV_OPEN_ERROR_CODES: OpenErrorCodes = OpenErrorCodes {
    not_found: HeatmapError::LcovOpenNotFound,
    permission_denied: HeatmapError::LcovOpenPermissionDenied,
    transient: HeatmapError::LcovOpenTransient,
    // Read-only open cannot report AlreadyExists; if an OS ever does, it is "other".
    already_exists: HeatmapError::LcovOpenOther,
    other: HeatmapError::LcovOpenOther,
};

const SOURCE_OPEN_ERROR_CODES: OpenErrorCodes = OpenErrorCodes {
    not_found: HeatmapError::SrcOpenNotFound,
    permission_denied: HeatmapError::SrcOpenPermissionDenied,
    transient: HeatmapError::SrcOpenTransient,
    // Read-only open cannot report AlreadyExists; if an OS ever does, it is "other".
    already_exists: HeatmapError::SrcOpenOther,
    other: HeatmapError::SrcOpenOther,
};

const REPORT_OPEN_ERROR_CODES: OpenErrorCodes = OpenErrorCodes {
    not_found: HeatmapError::RptOpenNotFound,
    permission_denied: HeatmapError::RptOpenPermissionDenied,
    transient: HeatmapError::RptOpenTransient,
    already_exists: HeatmapError::RptOpenAlreadyExists,
    other: HeatmapError::RptOpenOther,
};

/// Everything the report writers need (borrowed; no copies).
struct ReportInputs<'a> {
    lcov_input_path: &'a Path,
    report_file_path: &'a Path,
    sites_tsv_file_path: &'a Path,
    records: &'a [FileCoverageRecord],
    function_sites: &'a [HeatSite],
    function_summary: &'a HeatKindSummary,
    loop_sites: &'a [HeatSite],
    loop_summary: &'a HeatKindSummary,
    loop_scan_statistics: &'a LoopScanStatistics,
    /// Per-file details: skipped and partly scanned files.
    loop_scan_file_notes: &'a LoopScanFileNotes,
    top_n_limit: usize,
    /// Duplicate `FN` names within a file (integrity check; expected 0).
    duplicate_function_name_count: usize,
    /// Source paths listed in more than one `SF:` record (integrity check; expected 0).
    duplicate_source_path_count: usize,
    /// Optional run description.
    run_metadata: &'a RunMetadata,
}

// ============================================================================
// Public entry points
// ============================================================================

/// Runs end to end using the process command line.
///
/// Steps: parse args -> parse LCOV -> function sites -> loop sites ->
/// summarize -> write text report + TSV -> print report to stdout.
pub fn run_heatmap_cli() -> Result<(), HeatmapError> {
    let run_configuration = parse_cli_arguments(std::env::args_os())?;
    run_heatmap_with_configuration(&run_configuration)
}

/// Appends `unix_seconds=<n> error_code=<code>` to the error log next to the
/// executable. Logs only the numeric code (no paths, no user data).
pub fn append_error_code_to_log(error_code: HeatmapError) -> Result<(), HeatmapError> {
    let executable_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_io_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: current_exe failed: {}",
                HeatmapError::LogExecutablePathUnavailable.code(),
                _io_error
            );
            return Err(HeatmapError::LogExecutablePathUnavailable);
        }
    };
    let executable_directory = match executable_path.parent() {
        Some(directory) => directory,
        None => return Err(HeatmapError::LogExecutableParentMissing),
    };
    let error_log_path = executable_directory.join(ERROR_LOG_FILE_NAME);

    let unix_seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_clock_error) => return Err(HeatmapError::LogClockBeforeEpoch),
    };

    let mut error_log_file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&error_log_path)
    {
        Ok(file) => file,
        Err(_io_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: error log open failed: {}",
                HeatmapError::LogOpenFailed.code(),
                _io_error
            );
            return Err(HeatmapError::LogOpenFailed);
        }
    };

    match writeln!(
        error_log_file,
        "unix_seconds={} error_code={}",
        unix_seconds,
        error_code.code()
    ) {
        Ok(()) => Ok(()),
        Err(_io_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: error log write failed: {}",
                HeatmapError::LogWriteFailed.code(),
                _io_error
            );
            Err(HeatmapError::LogWriteFailed)
        }
    }
}

// ============================================================================
// Orchestration
// ============================================================================

/// Runs the full count-heat pipeline for an already-validated configuration.
///
/// # Project context
/// This is the single orchestration point of the tool. Each step consumes the
/// previous step's output; nothing is written to disk until every report has
/// been rendered successfully in memory, so a failure never leaves a
/// half-written report next to a complete one.
///
/// # Steps
/// 0. Refuse an existing `--out-dir` (preflight; nothing read or written).
/// 1. Open and parse the LCOV file (fatal on failure: no LCOV, no data).
/// 2. Build function sites (exact LLVM entry counts; monomorphized instances
///    at one source line merged), then sort + summarize them.
/// 3. Scan non-cold source files for loop headers (Tier 2: an unreadable file
///    is skipped and counted, never fatal), then sort + summarize loop sites.
/// 4. Render the text report and the all-sites TSV into memory.
/// 5. Create the output directory (atomically; must be new), write both
///    files (create-new), then print the text report to stdout.
///
/// # Arguments
/// - `run_configuration`: validated paths (absolute) and Top-N limit.
///   Each value is re-checked through its `.get()` before use.
///
/// # Returns
/// - `Ok(())` when both files were written and the report was printed.
/// - `Err(HeatmapError)`: the unique code of the first failing step,
///   propagated unchanged to `main` (Tier 3), which logs the numeric code.
///
/// # Modes
/// - Production: no printing here; errors are returned as codes only.
/// - Debug: callees print verbose diagnostics via gated `eprintln!`.
fn run_heatmap_with_configuration(
    run_configuration: &HeatmapRunConfiguration,
) -> Result<(), HeatmapError> {
    let lcov_input_path = run_configuration.lcov_input_path.ap_get()?;
    let output_directory_path = run_configuration.output_directory_path.ap_get()?;
    let top_n_limit = usize::from(run_configuration.top_n.tnc_get()?);

    // Step 0: output-directory safety preflight (fail fast, before any work).
    check_output_path_is_new(output_directory_path)?;

    // Step 1: parse LCOV (fatal on failure: without it there is no data).
    let lcov_file = open_file_with_retry(
        lcov_input_path,
        FileOpenPurpose::ReadExisting,
        LCOV_OPEN_ERROR_CODES,
    )?;
    let mut lcov_reader = BufReader::new(lcov_file);
    let coverage_records = parse_lcov_reader(&mut lcov_reader)?;

    // Step 2: function sites (exact entry counts), sorted + summarized together.
    let (mut function_sites, duplicate_function_name_count) =
        build_function_sites(&coverage_records)?;
    let function_summary = sort_and_summarize_sites(&mut function_sites)?;

    // Step 3: loop sites (lexical scan; per-file failures absorbed at Tier 2),
    // sorted + summarized together.
    let (mut loop_sites, loop_scan_statistics, loop_scan_file_notes) =
        scan_all_files_for_loops(&coverage_records);
    check_loop_scan_totals(&loop_scan_statistics, &loop_scan_file_notes)?;
    let loop_summary = sort_and_summarize_sites(&mut loop_sites)?;

    // Step 4: render reports into memory (no disk writes yet).
    let report_file_path = output_directory_path.join(REPORT_FILE_NAME);
    let sites_tsv_file_path = output_directory_path.join(SITES_TSV_FILE_NAME);
    let report_inputs = ReportInputs {
        lcov_input_path,
        report_file_path: &report_file_path,
        sites_tsv_file_path: &sites_tsv_file_path,
        records: &coverage_records,
        function_sites: &function_sites,
        function_summary: &function_summary,
        loop_sites: &loop_sites,
        loop_summary: &loop_summary,
        loop_scan_statistics: &loop_scan_statistics,
        loop_scan_file_notes: &loop_scan_file_notes,
        top_n_limit,
        duplicate_function_name_count,
        duplicate_source_path_count: count_duplicate_source_paths(&coverage_records),
        run_metadata: &run_configuration.run_metadata,
    };

    let mut report_bytes: Vec<u8> = Vec::with_capacity(REPORT_BUFFER_INITIAL_CAPACITY);
    write_text_report(&mut report_bytes, &report_inputs)?;
    let mut sites_tsv_bytes: Vec<u8> = Vec::with_capacity(REPORT_BUFFER_INITIAL_CAPACITY);
    write_sites_tsv(&mut sites_tsv_bytes, &report_inputs)?;

    // Step 5: create the new output directory (atomic), write files, then stdout.
    create_new_output_directory(output_directory_path)?;
    write_bytes_to_new_file(&report_file_path, &report_bytes)?;
    write_bytes_to_new_file(&sites_tsv_file_path, &sites_tsv_bytes)?;

    let standard_output = std::io::stdout();
    let mut standard_output_lock = standard_output.lock();
    if let Err(_io_error) = standard_output_lock.write_all(&report_bytes) {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: stdout write failed: {}",
            HeatmapError::RptStdoutWriteFailed.code(),
            _io_error
        );
        return Err(HeatmapError::RptStdoutWriteFailed);
    }
    if let Err(_io_error) = standard_output_lock.flush() {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: stdout flush failed: {}",
            HeatmapError::RptStdoutWriteFailed.code(),
            _io_error
        );
        return Err(HeatmapError::RptStdoutWriteFailed);
    }
    Ok(())
}

// ============================================================================
// Command line
// ============================================================================

/// Raw `--flag value` values, collected before any validation.
/// One field per flag; the field count equals `MAX_CLI_FLAG_PAIRS`.
#[derive(Default)]
struct RawCliFlagValues {
    lcov: Option<OsString>,
    out_dir: Option<OsString>,
    top_n: Option<OsString>,
    run_label: Option<OsString>,
    run_duration_secs: Option<OsString>,
    work_units: Option<OsString>,
    work_unit_name: Option<OsString>,
}

/// Returns a flag value as UTF-8 text, or `not_utf8_code` (input validation).
fn flag_value_as_text(
    value_argument: &OsString,
    not_utf8_code: HeatmapError,
) -> Result<&str, HeatmapError> {
    match value_argument.to_str() {
        Some(text) => Ok(text),
        None => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: flag value is not UTF-8: {:?}",
                not_utf8_code.code(),
                value_argument
            );
            Err(not_utf8_code)
        }
    }
}

/// Parses a flag value as `u64`, with per-flag codes (input validation).
fn parse_u64_flag_value(
    value_argument: &OsString,
    not_utf8_code: HeatmapError,
    not_a_number_code: HeatmapError,
) -> Result<u64, HeatmapError> {
    let value_text = flag_value_as_text(value_argument, not_utf8_code)?;
    match value_text.parse::<u64>() {
        Ok(value) => Ok(value),
        Err(_parse_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: not a u64 number {:?}: {}",
                not_a_number_code.code(),
                value_text,
                _parse_error
            );
            Err(not_a_number_code)
        }
    }
}

/// Parses the command line into a validated configuration.
///
/// # Steps
/// 1. Collect `--flag value` pairs (any order, each flag at most once,
///    at most `MAX_CLI_FLAG_PAIRS` pairs) into `RawCliFlagValues`.
/// 2. Required flags: `--lcov` (104), `--out-dir` (105).
/// 3. `--top-n` (default `DEFAULT_TOP_N`).
/// 4. Run metadata (all optional); `--work-units` and `--work-unit-name`
///    must be given together (115 / 116).
/// 5. Build the enforced types (paths absolute, values in range).
///
/// Generic over the iterator so tests can pass synthetic arguments.
fn parse_cli_arguments<I>(arguments: I) -> Result<HeatmapRunConfiguration, HeatmapError>
where
    I: Iterator<Item = OsString>,
{
    let mut remaining_arguments = arguments.skip(1); // skip program name
    let mut raw_values = RawCliFlagValues::default();
    let mut reached_end_of_arguments = false;

    // Step 1: collect pairs (bounded by MAX_CLI_FLAG_PAIRS).
    for _flag_pair_index in 0..MAX_CLI_FLAG_PAIRS {
        let flag_argument = match remaining_arguments.next() {
            Some(flag) => flag,
            None => {
                reached_end_of_arguments = true;
                break;
            }
        };
        let value_argument = match remaining_arguments.next() {
            Some(value) => value,
            None => return Err(HeatmapError::CliMissingFlagValue),
        };
        let value_slot = match flag_argument.to_str() {
            Some("--lcov") => &mut raw_values.lcov,
            Some("--out-dir") => &mut raw_values.out_dir,
            Some("--top-n") => &mut raw_values.top_n,
            Some("--run-label") => &mut raw_values.run_label,
            Some("--run-duration-secs") => &mut raw_values.run_duration_secs,
            Some("--work-units") => &mut raw_values.work_units,
            Some("--work-unit-name") => &mut raw_values.work_unit_name,
            _ => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: unknown flag: {:?}",
                    HeatmapError::CliUnknownFlag.code(),
                    flag_argument
                );
                return Err(HeatmapError::CliUnknownFlag);
            }
        };
        if value_slot.is_some() {
            return Err(HeatmapError::CliDuplicateFlag);
        }
        *value_slot = Some(value_argument);
    }

    if !reached_end_of_arguments && remaining_arguments.next().is_some() {
        return Err(HeatmapError::CliTooManyArguments);
    }

    // Step 2: required flags.
    let lcov_path = match raw_values.lcov {
        Some(value) => PathBuf::from(value),
        None => return Err(HeatmapError::CliMissingLcovPath),
    };
    let output_directory = match raw_values.out_dir {
        Some(value) => PathBuf::from(value),
        None => return Err(HeatmapError::CliMissingOutputDirectory),
    };

    // Step 3: --top-n.
    let top_n_value = match &raw_values.top_n {
        None => DEFAULT_TOP_N,
        Some(value_argument) => {
            let top_n_text = flag_value_as_text(value_argument, HeatmapError::CliTopNNotUtf8)?;
            match top_n_text.parse::<u16>() {
                Ok(parsed_top_n) => parsed_top_n,
                Err(_parse_error) => {
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "HIX-{}: --top-n parse failed: {}",
                        HeatmapError::CliTopNNotANumber.code(),
                        _parse_error
                    );
                    return Err(HeatmapError::CliTopNNotANumber);
                }
            }
        }
    };

    // Step 4: run metadata (optional).
    let run_label = match &raw_values.run_label {
        None => None,
        Some(value_argument) => Some(RunLabel::rl_new(flag_value_as_text(
            value_argument,
            HeatmapError::CliRunLabelNotUtf8,
        )?)?),
    };
    let run_duration = match &raw_values.run_duration_secs {
        None => None,
        Some(value_argument) => Some(RunDurationSeconds::rds_new(parse_u64_flag_value(
            value_argument,
            HeatmapError::CliRunDurationNotUtf8,
            HeatmapError::CliRunDurationNotANumber,
        )?)?),
    };
    let work_units = match (&raw_values.work_units, &raw_values.work_unit_name) {
        (None, None) => None,
        (Some(_), None) => return Err(HeatmapError::CliWorkUnitsWithoutName),
        (None, Some(_)) => return Err(HeatmapError::CliWorkUnitNameWithoutUnits),
        (Some(count_argument), Some(name_argument)) => {
            let count_value = parse_u64_flag_value(
                count_argument,
                HeatmapError::CliWorkUnitsNotUtf8,
                HeatmapError::CliWorkUnitsNotANumber,
            )?;
            let name_text =
                flag_value_as_text(name_argument, HeatmapError::CliWorkUnitNameNotUtf8)?;
            Some(WorkUnits {
                count: WorkUnitCount::wuc_new(count_value)?,
                name: WorkUnitName::wun_new(name_text)?,
            })
        }
    };

    // Step 5: enforced types.
    Ok(HeatmapRunConfiguration {
        lcov_input_path: AbsolutePath::ap_new(lcov_path)?,
        output_directory_path: AbsolutePath::ap_new(output_directory)?,
        top_n: TopNCount::tnc_new(top_n_value)?,
        run_metadata: RunMetadata {
            run_label,
            run_duration,
            work_units,
        },
    })
}

// ============================================================================
// File helpers
// ============================================================================

/// Preflight: succeeds only if nothing exists at `output_directory_path`.
///
/// # Project context
/// Run and analysis folders are a permanent record (`run_NNN_<scenario>`,
/// `analysis_NNN_<purpose>`). Reusing a name could overwrite or mix earlier
/// results. This check runs before the LCOV is parsed, so a name collision
/// stops the run at once instead of after minutes of analysis.
///
/// `symlink_metadata` is used (not `exists()`), so a dangling symlink also
/// counts as "exists", and a permission problem is reported, not mistaken
/// for "does not exist".
///
/// # Returns
/// - `Ok(())`: the path does not exist.
/// - `Err(RptOutputPathAlreadyExists)`: any entry exists there (input validation).
/// - `Err(RptOutputPathCheckFailed)`: existence could not be determined.
///
/// # Modes
/// Input validation (user-chosen path): debug builds print the path; no panic.
fn check_output_path_is_new(output_directory_path: &Path) -> Result<(), HeatmapError> {
    match fs::symlink_metadata(output_directory_path) {
        Ok(_existing_metadata) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: --out-dir already exists (HIX never overwrites): {}",
                HeatmapError::RptOutputPathAlreadyExists.code(),
                output_directory_path.display()
            );
            Err(HeatmapError::RptOutputPathAlreadyExists)
        }
        Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_io_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: cannot check --out-dir {}: {}",
                HeatmapError::RptOutputPathCheckFailed.code(),
                output_directory_path.display(),
                _io_error
            );
            Err(HeatmapError::RptOutputPathCheckFailed)
        }
    }
}

/// Creates the output directory, which must not exist; creates its parent if missing.
///
/// # Project context
/// The second half of output-directory safety. `fs::create_dir` fails if
/// the path exists, so creation and the existence check are one atomic step:
/// if anything created the directory after `check_output_path_is_new`, this
/// returns an error instead of writing into it. Only the parent (e.g. the
/// `run_NNN_<scenario>` folder) may already exist or be created here.
///
/// # Returns
/// - `Ok(())`: the directory was newly created by this call.
/// - `Err(RptOutputPathHasNoParent)`: the path has no parent (e.g. `/`).
/// - `Err(RptOutputParentCreateFailed)`: the parent could not be created.
/// - `Err(RptOutputDirectoryAppearedDuringRun)`: the path exists now.
/// - `Err(RptCreateDirectoryFailed)`: any other creation failure.
fn create_new_output_directory(output_directory_path: &Path) -> Result<(), HeatmapError> {
    let parent_directory = match output_directory_path.parent() {
        Some(parent) => parent,
        None => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: --out-dir has no parent: {}",
                HeatmapError::RptOutputPathHasNoParent.code(),
                output_directory_path.display()
            );
            return Err(HeatmapError::RptOutputPathHasNoParent);
        }
    };
    if let Err(_io_error) = fs::create_dir_all(parent_directory) {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: create parent {} failed: {}",
            HeatmapError::RptOutputParentCreateFailed.code(),
            parent_directory.display(),
            _io_error
        );
        return Err(HeatmapError::RptOutputParentCreateFailed);
    }
    match fs::create_dir(output_directory_path) {
        Ok(()) => Ok(()),
        Err(io_error) if io_error.kind() == std::io::ErrorKind::AlreadyExists => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: --out-dir appeared during the run: {}",
                HeatmapError::RptOutputDirectoryAppearedDuringRun.code(),
                output_directory_path.display()
            );
            Err(HeatmapError::RptOutputDirectoryAppearedDuringRun)
        }
        Err(_io_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: create_dir failed: {}",
                HeatmapError::RptCreateDirectoryFailed.code(),
                _io_error
            );
            Err(HeatmapError::RptCreateDirectoryFailed)
        }
    }
}

/// Maps an I/O error kind to the caller's site-specific error codes.
fn classify_open_error(io_error_kind: std::io::ErrorKind, codes: OpenErrorCodes) -> HeatmapError {
    match io_error_kind {
        std::io::ErrorKind::AlreadyExists => codes.already_exists,
        std::io::ErrorKind::NotFound => codes.not_found,
        std::io::ErrorKind::PermissionDenied => codes.permission_denied,
        std::io::ErrorKind::Interrupted
        | std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::TimedOut => codes.transient,
        _ => codes.other,
    }
}

/// Opens a file with Tier-1 bounded retry (only for retryable codes).
fn open_file_with_retry(
    file_path: &Path,
    purpose: FileOpenPurpose,
    codes: OpenErrorCodes,
) -> Result<File, HeatmapError> {
    for attempt_index in 0..MAX_OPEN_ATTEMPTS {
        let open_result = match purpose {
            FileOpenPurpose::ReadExisting => File::open(file_path),
            FileOpenPurpose::CreateNew => OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(file_path),
        };
        match open_result {
            Ok(opened_file) => return Ok(opened_file),
            Err(io_error) => {
                let error_code = classify_open_error(io_error.kind(), codes);
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: open attempt {} failed for {}: {}",
                    error_code.code(),
                    attempt_index,
                    file_path.display(),
                    io_error
                );
                if !error_code.is_retryable() {
                    return Err(error_code);
                }
                // Last attempt failed: the result is decided, so do not sleep.
                let next_attempt_index = attempt_index.saturating_add(1);
                if next_attempt_index >= MAX_OPEN_ATTEMPTS {
                    return Err(error_code);
                }
                let backoff_milliseconds =
                    OPEN_RETRY_BACKOFF_STEP_MS.saturating_mul(u64::from(next_attempt_index));
                std::thread::sleep(Duration::from_millis(backoff_milliseconds));
            }
        }
    }
    // Reached only if MAX_OPEN_ATTEMPTS is 0 (no attempt was made).
    Err(codes.transient)
}

/// Creates/truncates a file and writes all bytes.
fn write_bytes_to_new_file(file_path: &Path, file_bytes: &[u8]) -> Result<(), HeatmapError> {
    let mut output_file = open_file_with_retry(
        file_path,
        FileOpenPurpose::CreateNew,
        REPORT_OPEN_ERROR_CODES,
    )?;
    if let Err(_io_error) = output_file.write_all(file_bytes) {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: write failed: {}",
            HeatmapError::RptFileWriteFailed.code(),
            _io_error
        );
        return Err(HeatmapError::RptFileWriteFailed);
    }
    if let Err(_io_error) = output_file.flush() {
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: flush failed: {}",
            HeatmapError::RptFlushFailed.code(),
            _io_error
        );
        return Err(HeatmapError::RptFlushFailed);
    }
    Ok(())
}

/// Reads one line (including `\n`) into `line_buffer`, never more than
/// `MAX_LINE_BYTES` (+1 to detect overflow). Returns bytes read; 0 = EOF.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line_buffer: &mut Vec<u8>,
    read_failed_code: HeatmapError,
    line_too_long_code: HeatmapError,
) -> Result<usize, HeatmapError> {
    line_buffer.clear();
    let read_limit = (MAX_LINE_BYTES as u64).saturating_add(1);
    let mut limited_reader = Read::take(&mut *reader, read_limit);
    match limited_reader.read_until(b'\n', line_buffer) {
        Ok(bytes_read) => {
            if bytes_read > MAX_LINE_BYTES {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: line exceeds {} bytes",
                    line_too_long_code.code(),
                    MAX_LINE_BYTES
                );
                return Err(line_too_long_code);
            }
            Ok(bytes_read)
        }
        Err(_io_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: read failed: {}",
                read_failed_code.code(),
                _io_error
            );
            Err(read_failed_code)
        }
    }
}

/// Reads one source-file line for the loop scan. A line longer than
/// `MAX_LINE_BYTES` is NOT an error: its start is kept and its rest discarded.
///
/// # Project context
/// Some files in large projects are generated, with whole data tables written
/// on one line.
/// The loop scan only ever looks at the *start* of a line (loop keywords,
/// `//`, `/*`), so keeping the start and discarding the rest loses nothing
/// the scan uses. The LCOV parser does not use this function: an over-long
/// LCOV line still means a corrupt file and stays fatal.
///
/// # Steps
/// 1. Read up to `MAX_LINE_BYTES + 1` bytes, stopping after a newline.
/// 2. 0 bytes: end of file. At most `MAX_LINE_BYTES` bytes: a complete line.
/// 3. More than `MAX_LINE_BYTES` bytes: an over-long line.
///    - If the last byte kept is the newline, the line has already ended
///      (it was exactly one byte too long). Nothing is discarded. Discarding
///      here would destroy the next line and shift every later line number.
///    - Otherwise discard up to and including the next newline (or end of
///      file) with `discard_rest_of_source_line`, checking for `*/`.
///
/// # Arguments
/// - `reader`: buffered source text (a file in production, a `Cursor` in tests).
/// - `line_buffer`: cleared, then filled with the line (or the line's start).
/// - `skip_cap_bytes`: maximum discarded remainder per line. Production passes
///   `MAX_SKIPPED_LINE_BYTES`; tests pass small values.
///
/// # Returns
/// - `Ok(SourceLineReadOutcome)`: see the enum for each case.
/// - `Err(SrcReadFailed)`: reading the line (or its start) failed.
/// - `Err(SrcLineExceedsSkipCap | SrcSkipReadFailed | SrcSkipReadCallLimit)`:
///   from `discard_rest_of_source_line`.
///
/// All errors are absorbed per file at Tier 2 by `scan_all_files_for_loops`.
///
/// # Modes
/// Debug builds print one diagnostic line per over-long line (no path).
fn read_source_line_skipping_overlong<R: BufRead>(
    reader: &mut R,
    line_buffer: &mut Vec<u8>,
    skip_cap_bytes: usize,
) -> Result<SourceLineReadOutcome, HeatmapError> {
    line_buffer.clear();
    let read_limit = (MAX_LINE_BYTES as u64).saturating_add(1);
    let kept_byte_count = {
        let mut limited_reader = Read::take(&mut *reader, read_limit);
        match limited_reader.read_until(b'\n', line_buffer) {
            Ok(bytes_read) => bytes_read,
            Err(_io_error) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: source read failed: {}",
                    HeatmapError::SrcReadFailed.code(),
                    _io_error
                );
                return Err(HeatmapError::SrcReadFailed);
            }
        }
    };

    if kept_byte_count == 0 {
        return Ok(SourceLineReadOutcome::EndOfInput);
    }
    if kept_byte_count <= MAX_LINE_BYTES {
        return Ok(SourceLineReadOutcome::CompleteLine);
    }

    #[cfg(debug_assertions)]
    eprintln!(
        "source line exceeds {} bytes: scanning its start, discarding the rest",
        MAX_LINE_BYTES
    );

    // The line ended exactly at the limit: nothing left to discard.
    if line_buffer.last() == Some(&b'\n') {
        return Ok(SourceLineReadOutcome::OverLongLineStartKept {
            discarded_part_contains_block_comment_end: false,
        });
    }

    // A `*` at the very end of the kept start may pair with a `/` at the very
    // beginning of the discarded part to form `*/`.
    let kept_part_ended_with_star = line_buffer.last() == Some(&b'*');
    let discarded_part_contains_block_comment_end =
        discard_rest_of_source_line(reader, kept_part_ended_with_star, skip_cap_bytes)?;
    Ok(SourceLineReadOutcome::OverLongLineStartKept {
        discarded_part_contains_block_comment_end,
    })
}

/// Reads and discards the rest of the current line, up to and including the
/// next newline (or end of file), and reports whether it contained `*/`.
///
/// # Project context
/// Used only for over-long source lines (see `read_source_line_skipping_overlong`).
/// The discarded bytes are never stored, so memory use stays constant no
/// matter how long the line is. The `*/` check keeps block-comment tracking
/// correct when a comment ends inside the discarded part.
///
/// # Steps (bounded loop)
/// 1. Ask the reader for its next chunk of buffered bytes (`fill_buf`).
///    - "Interrupted": try again (uses the extra read-call allowance).
///    - Empty chunk: end of file, so the line is finished.
/// 2. Take the chunk up to and including the first newline, or the whole
///    chunk if it has no newline.
/// 3. Check those bytes for `*/`, carrying "previous byte was `*`" across
///    chunks so a `*/` split between two chunks is still seen.
/// 4. Mark those bytes as consumed, and add them to the discarded total.
/// 5. If the total exceeds `skip_cap_bytes`: error. If a newline was
///    reached: done. Otherwise repeat.
///
/// The cap check comes before the newline check, so the result depends only
/// on the length of the remainder, not on how the reader splits it into chunks.
///
/// # Arguments
/// - `reader`: positioned just after the kept start of the over-long line.
/// - `kept_part_ended_with_star`: true if the last kept byte was `*`.
/// - `skip_cap_bytes`: maximum bytes to discard.
///
/// # Returns
/// - `Ok(true)` if `*/` occurred in the discarded part (or across the
///   kept/discarded boundary); `Ok(false)` otherwise.
/// - `Err(SrcSkipReadFailed)`: a read failed (other than "interrupted").
/// - `Err(SrcLineExceedsSkipCap)`: the remainder is longer than `skip_cap_bytes`.
/// - `Err(SrcSkipReadCallLimit)`: the read-call bound was reached (only
///   possible with endlessly interrupted reads; a safety bound).
fn discard_rest_of_source_line<R: BufRead>(
    reader: &mut R,
    kept_part_ended_with_star: bool,
    skip_cap_bytes: usize,
) -> Result<bool, HeatmapError> {
    // Each successful read call discards at least one byte, and the cap check
    // stops the loop once more than `skip_cap_bytes` have been discarded, so
    // at most `skip_cap_bytes + 1` successful calls occur. Interrupted calls
    // discard nothing and are covered by the extra allowance.
    let maximum_read_calls = skip_cap_bytes
        .saturating_add(1)
        .saturating_add(SKIP_LINE_EXTRA_READ_CALLS);
    let mut previous_byte_was_star = kept_part_ended_with_star;
    let mut block_comment_end_seen = false;
    let mut discarded_byte_count: usize = 0;

    for _read_call_index in 0..maximum_read_calls {
        let available_bytes = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(io_error) if io_error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_io_error) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: read failed while discarding over-long line: {}",
                    HeatmapError::SrcSkipReadFailed.code(),
                    _io_error
                );
                return Err(HeatmapError::SrcSkipReadFailed);
            }
        };
        if available_bytes.is_empty() {
            // End of file inside the over-long line: the line is finished.
            return Ok(block_comment_end_seen);
        }

        let (consume_length, line_ended) =
            match available_bytes.iter().position(|byte| *byte == b'\n') {
                Some(newline_index) => (newline_index.saturating_add(1), true),
                None => (available_bytes.len(), false),
            };

        for &byte in available_bytes.iter().take(consume_length) {
            if previous_byte_was_star && byte == b'/' {
                block_comment_end_seen = true;
            }
            previous_byte_was_star = byte == b'*';
        }

        reader.consume(consume_length);
        discarded_byte_count = discarded_byte_count.saturating_add(consume_length);

        if discarded_byte_count > skip_cap_bytes {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: over-long line remainder exceeds {} bytes; skipping file",
                HeatmapError::SrcLineExceedsSkipCap.code(),
                skip_cap_bytes
            );
            return Err(HeatmapError::SrcLineExceedsSkipCap);
        }
        if line_ended {
            return Ok(block_comment_end_seen);
        }
    }

    #[cfg(debug_assertions)]
    eprintln!(
        "HIX-{}: discard read-call limit {} reached",
        HeatmapError::SrcSkipReadCallLimit.code(),
        maximum_read_calls
    );
    Err(HeatmapError::SrcSkipReadCallLimit)
}

// ============================================================================
// LCOV parsing
// ============================================================================

/// Parses an LCOV stream into per-file coverage records.
/// Recognized: `SF:`, `FN:`, `FNDA:`, `DA:`, `end_of_record`; others ignored.
fn parse_lcov_reader<R: BufRead>(reader: &mut R) -> Result<Vec<FileCoverageRecord>, HeatmapError> {
    let mut completed_records: Vec<FileCoverageRecord> = Vec::new();
    let mut current_record: Option<FileCoverageRecord> = None;
    let mut line_buffer: Vec<u8> = Vec::with_capacity(4096);
    let mut total_coverage_entries: usize = 0;

    for _lcov_line_index in 0..MAX_LCOV_LINES {
        let bytes_read = read_bounded_line(
            reader,
            &mut line_buffer,
            HeatmapError::LcovReadFailed,
            HeatmapError::LcovLineTooLong,
        )?;
        if bytes_read == 0 {
            return finish_lcov_parse(completed_records, current_record);
        }
        let lcov_line_text = match std::str::from_utf8(&line_buffer) {
            Ok(text) => text.trim_end(),
            Err(_utf8_error) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: lcov line not UTF-8: {}",
                    HeatmapError::LcovNotUtf8.code(),
                    _utf8_error
                );
                return Err(HeatmapError::LcovNotUtf8);
            }
        };
        parse_one_lcov_line(
            lcov_line_text,
            &mut current_record,
            &mut completed_records,
            &mut total_coverage_entries,
        )?;
    }
    Err(HeatmapError::LcovTooManyLines)
}

/// End-of-input checks for LCOV parsing.
fn finish_lcov_parse(
    completed_records: Vec<FileCoverageRecord>,
    current_record: Option<FileCoverageRecord>,
) -> Result<Vec<FileCoverageRecord>, HeatmapError> {
    if current_record.is_some() {
        return Err(HeatmapError::LcovUnterminatedRecord);
    }
    if completed_records.is_empty() {
        return Err(HeatmapError::LcovNoData);
    }
    Ok(completed_records)
}

/// Applies one LCOV line to the parser state.
fn parse_one_lcov_line(
    lcov_line_text: &str,
    current_record: &mut Option<FileCoverageRecord>,
    completed_records: &mut Vec<FileCoverageRecord>,
    total_coverage_entries: &mut usize,
) -> Result<(), HeatmapError> {
    if let Some(source_path_text) = lcov_line_text.strip_prefix("SF:") {
        if current_record.is_some() {
            return Err(HeatmapError::LcovMalformedRecord); // nested SF
        }
        if completed_records.len() >= MAX_SOURCE_FILES {
            return Err(HeatmapError::LcovTooManyFiles);
        }
        *current_record = Some(FileCoverageRecord::new(source_path_text));
        return Ok(());
    }

    if lcov_line_text == "end_of_record" {
        return match current_record.take() {
            Some(finished_record) => {
                completed_records.push(finished_record);
                Ok(())
            }
            None => Err(HeatmapError::LcovRecordOutsideFile),
        };
    }

    let is_used_entry = lcov_line_text.starts_with("FN:")
        || lcov_line_text.starts_with("FNDA:")
        || lcov_line_text.starts_with("DA:");
    if !is_used_entry {
        // TN, FNF, FNH, LF, LH, BRDA, BRF, BRH, blank
        return Ok(());
    }

    let record = match current_record.as_mut() {
        Some(record) => record,
        None => return Err(HeatmapError::LcovRecordOutsideFile),
    };
    *total_coverage_entries = match total_coverage_entries.checked_add(1) {
        Some(new_total) if new_total <= MAX_COVERAGE_ENTRIES => new_total,
        _ => return Err(HeatmapError::LcovTooManyEntries),
    };

    if let Some(entry_text) = lcov_line_text.strip_prefix("FN:") {
        // FN:<line>,<function name>   (name may contain commas: split once)
        let (line_text, function_name) = match entry_text.split_once(',') {
            Some(parts) => parts,
            None => return Err(HeatmapError::LcovMalformedRecord),
        };
        let line_number = parse_lcov_line_number(line_text)?;
        record
            .function_definitions
            .push((line_number, function_name.to_string()));
    } else if let Some(entry_text) = lcov_line_text.strip_prefix("FNDA:") {
        // FNDA:<count>,<function name>
        let (count_text, function_name) = match entry_text.split_once(',') {
            Some(parts) => parts,
            None => return Err(HeatmapError::LcovMalformedRecord),
        };
        let entry_count = parse_lcov_count(count_text)?;
        let count_slot = record
            .function_entry_counts
            .entry(function_name.to_string())
            .or_insert(0);
        *count_slot = match count_slot.checked_add(entry_count) {
            Some(sum) => sum,
            None => return Err(HeatmapError::LcovCountOverflow),
        };
    } else if let Some(entry_text) = lcov_line_text.strip_prefix("DA:") {
        // DA:<line>,<count>[,<checksum>]
        let mut entry_fields = entry_text.splitn(3, ',');
        let line_text = match entry_fields.next() {
            Some(text) => text,
            None => return Err(HeatmapError::LcovMalformedRecord),
        };
        let count_text = match entry_fields.next() {
            Some(text) => text,
            None => return Err(HeatmapError::LcovMalformedRecord),
        };
        let line_number = parse_lcov_line_number(line_text)?;
        let line_count = parse_lcov_count(count_text)?;
        let count_slot = record.line_execution_counts.entry(line_number).or_insert(0);
        if line_count > *count_slot {
            *count_slot = line_count;
        }
        if line_count > record.max_line_execution_count {
            record.max_line_execution_count = line_count;
        }
    }
    Ok(())
}

/// Parses an LCOV line-number field into a validated `SourceLineNumber`.
fn parse_lcov_line_number(line_text: &str) -> Result<SourceLineNumber, HeatmapError> {
    let raw_line = match line_text.trim().parse::<u32>() {
        Ok(value) => value,
        Err(_parse_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: bad line number {:?}: {}",
                HeatmapError::LcovBadLineNumber.code(),
                line_text,
                _parse_error
            );
            return Err(HeatmapError::LcovBadLineNumber);
        }
    };
    match SourceLineNumber::sln_new(raw_line) {
        Ok(line_number) => Ok(line_number),
        Err(_type_error) => Err(HeatmapError::LcovBadLineNumber),
    }
}

/// Parses an LCOV execution-count field.
fn parse_lcov_count(count_text: &str) -> Result<u64, HeatmapError> {
    match count_text.trim().parse::<u64>() {
        Ok(count) => Ok(count),
        Err(_parse_error) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: bad count {:?}: {}",
                HeatmapError::LcovBadCount.code(),
                count_text,
                _parse_error
            );
            Err(HeatmapError::LcovBadCount)
        }
    }
}

// ============================================================================
// Function sites
// ============================================================================

/// Builds one FUNCTION heat site per (source file, definition line).
///
/// # Project context
/// Function entry counts are the primary count-heat signal: exact LLVM
/// counters (not samples) for how often each function was entered during the
/// instrumented run. Identity is `source_path:line`, not the function name,
/// because (a) names may be mangled and (b) generic functions produce one
/// LCOV entry per monomorphized instance, all at the same source line.
///
/// # Merge rule
/// All instances defined at the same line are merged into one site: their
/// counts are summed and `merged_instance_count` records how many were merged.
/// The first instance's name is kept as `display_name`.
///
/// # Integrity check (duplicate names)
/// `FNDA` counts are stored by name, so two `FN` entries with the same name
/// in one file cannot be told apart: each would receive the shared total.
/// With mangled LCOV this does not happen. If the LCOV was demangled *before*
/// parsing, distinct instances can collapse to one name, which causes double
/// counting. The number of such duplicates is returned and shown in the
/// report's provenance block (expected: 0).
///
/// # Arguments
/// - `records`: parsed LCOV records, one per source file.
///
/// # Returns
/// - `Ok((function_sites, duplicate_function_name_count))`. Sites are in
///   LCOV order (NOT sorted): pass them to `sort_and_summarize_sites`.
/// - `Err(HeatmapError::AnaSiteIndexInvalid)`: internal index invariant broken.
/// - `Err(HeatmapError::AnaCountOverflow)`: merged count exceeded u64.
fn build_function_sites(
    records: &[FileCoverageRecord],
) -> Result<(Vec<HeatSite>, usize), HeatmapError> {
    let mut function_sites: Vec<HeatSite> = Vec::new();
    let mut duplicate_function_name_count: usize = 0;

    for (file_index, record) in records.iter().enumerate() {
        let mut site_index_by_line: HashMap<SourceLineNumber, usize> = HashMap::new();
        let mut function_names_seen: HashSet<&str> =
            HashSet::with_capacity(record.function_definitions.len());

        for (definition_line, function_name) in record.function_definitions.iter() {
            if !function_names_seen.insert(function_name.as_str()) {
                duplicate_function_name_count = duplicate_function_name_count.saturating_add(1);
            }

            let entry_count = record
                .function_entry_counts
                .get(function_name)
                .copied()
                .unwrap_or(0);

            match site_index_by_line.get(definition_line) {
                Some(&existing_site_index) => {
                    let existing_site = match function_sites.get_mut(existing_site_index) {
                        Some(site) => site,
                        None => {
                            #[cfg(all(debug_assertions, not(test)))]
                            debug_assert!(
                                false,
                                "HIX-{}: site index {} invalid",
                                HeatmapError::AnaSiteIndexInvalid.code(),
                                existing_site_index
                            );
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "HIX-{}: site index {} invalid",
                                HeatmapError::AnaSiteIndexInvalid.code(),
                                existing_site_index
                            );
                            return Err(HeatmapError::AnaSiteIndexInvalid);
                        }
                    };
                    existing_site.execution_count =
                        match existing_site.execution_count.checked_add(entry_count) {
                            Some(sum) => sum,
                            None => return Err(HeatmapError::AnaCountOverflow),
                        };
                    existing_site.merged_instance_count =
                        existing_site.merged_instance_count.saturating_add(1);
                }
                None => {
                    let new_site_index = function_sites.len();
                    function_sites.push(HeatSite {
                        source_file_index: file_index,
                        line_number: *definition_line,
                        display_name: function_name.clone(),
                        execution_count: entry_count,
                        merged_instance_count: 1,
                        enclosing_function_entry_count: None,
                    });
                    site_index_by_line.insert(*definition_line, new_site_index);
                }
            }
        }
    }
    Ok((function_sites, duplicate_function_name_count))
}

/// Counts source paths that appear in more than one `SF:` record.
///
/// # Project context
/// Integrity check, shown in provenance (expected 0). A single
/// `cargo llvm-cov report` lists each file once. A nonzero value (for
/// example, from concatenated LCOV files) means one file's sites appear
/// twice, each with only part of the counts.
///
/// # Returns
/// The number of `SF:` records whose path was already seen.
fn count_duplicate_source_paths(records: &[FileCoverageRecord]) -> usize {
    let mut source_paths_seen: HashSet<&str> = HashSet::with_capacity(records.len());
    let mut duplicate_source_path_count: usize = 0;
    for record in records.iter() {
        if !source_paths_seen.insert(record.source_path_text.as_str()) {
            duplicate_source_path_count = duplicate_source_path_count.saturating_add(1);
        }
    }
    duplicate_source_path_count
}

// ============================================================================
// Loop sites (lexical scan, no AST)
// ============================================================================
/// Scans every non-cold source file for loop headers and collects LOOP sites.
///
/// # Project context
/// This is the "prioritization step" plus the per-file loop scan. A file
/// whose every LCOV line count is 0 cannot contain a hot loop, so it is
/// skipped without being opened.
/// This is how the tool stays fast on very large codebases.
///
/// # Steps (per source file listed in the LCOV)
/// 1. Count the file in `files_total`.
/// 2. Skip it if it is cold (every line count is 0): counted, not listed.
/// 3. Skip it if its LCOV path is not absolute: counted and listed.
/// 4. Otherwise open and scan it (`scan_one_source_file`).
///    - Success: add its loop sites and counters. If it had over-long lines,
///      list it as partly scanned.
///    - Failure (Tier 2): skip the file, count and list the reason, continue.
/// 5. Sort the notes (see `LoopScanFileNotes`) so the report is deterministic.
///
/// # Returns
/// `(loop_sites, statistics, file_notes)`. Never fails: per-file problems
/// are absorbed, counted, and listed, so one unreadable file cannot stop the
/// analysis. Loop sites are in file order (NOT sorted): pass them to
/// `sort_and_summarize_sites`.
///
/// # Modes
/// Debug builds print the path and error for each skipped file. Production
/// builds print nothing; the counts and the listing appear in the report.
fn scan_all_files_for_loops(
    records: &[FileCoverageRecord],
) -> (Vec<HeatSite>, LoopScanStatistics, LoopScanFileNotes) {
    let mut all_loop_sites: Vec<HeatSite> = Vec::new();
    let mut scan_statistics = LoopScanStatistics::default();
    let mut file_notes = LoopScanFileNotes::default();

    for (file_index, record) in records.iter().enumerate() {
        scan_statistics.files_total = scan_statistics.files_total.saturating_add(1);

        // Prioritization step: an entirely cold file cannot contain a hot loop.
        if record.max_line_execution_count == 0 {
            scan_statistics.files_skipped_cold =
                scan_statistics.files_skipped_cold.saturating_add(1);
            continue;
        }

        let absolute_source_path =
            match AbsolutePath::ap_new(PathBuf::from(&record.source_path_text)) {
                Ok(path) => path,
                Err(type_error) => {
                    record_skipped_file(
                        &mut scan_statistics,
                        &mut file_notes,
                        file_index,
                        type_error,
                    );
                    continue;
                }
            };

        match scan_one_source_file(&absolute_source_path, file_index, record) {
            Ok(scan_outcome) => {
                scan_statistics.files_scanned = scan_statistics.files_scanned.saturating_add(1);
                scan_statistics.loop_headers_found = scan_statistics
                    .loop_headers_found
                    .saturating_add(scan_outcome.loop_headers_found);
                scan_statistics.loop_headers_without_line_data = scan_statistics
                    .loop_headers_without_line_data
                    .saturating_add(scan_outcome.loop_headers_without_line_data);
                scan_statistics.overlong_source_lines_total = scan_statistics
                    .overlong_source_lines_total
                    .saturating_add(scan_outcome.overlong_lines_found);
                if scan_outcome.overlong_lines_found > 0 {
                    scan_statistics.files_with_overlong_source_lines = scan_statistics
                        .files_with_overlong_source_lines
                        .saturating_add(1);
                    file_notes.partly_scanned_files.push(PartlyScannedFileNote {
                        source_file_index: file_index,
                        overlong_line_count: scan_outcome.overlong_lines_found,
                    });
                }
                all_loop_sites.extend(scan_outcome.loop_sites);
            }
            Err(scan_error) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "loop scan skipped {}: {}",
                    record.source_path_text, scan_error
                );
                // Tier 2: absorb, count and list by reason, continue with the next file.
                record_skipped_file(
                    &mut scan_statistics,
                    &mut file_notes,
                    file_index,
                    scan_error,
                );
            }
        }
    }

    file_notes
        .skipped_files
        .sort_by_key(|note| (note.reason, note.source_file_index));
    file_notes
        .partly_scanned_files
        .sort_by(|left_note, right_note| {
            right_note
                .overlong_line_count
                .cmp(&left_note.overlong_line_count)
                .then_with(|| {
                    left_note
                        .source_file_index
                        .cmp(&right_note.source_file_index)
                })
        });
    (all_loop_sites, scan_statistics, file_notes)
}

/// Counts one skipped (non-cold) file under its reason and lists it.
///
/// The counter and the listing are updated together, from one
/// classification (`FileSkipReason::from_scan_error`), so they cannot drift
/// apart. `check_loop_scan_totals` verifies this structurally (code 408).
fn record_skipped_file(
    scan_statistics: &mut LoopScanStatistics,
    file_notes: &mut LoopScanFileNotes,
    file_index: usize,
    scan_error: HeatmapError,
) {
    let skip_reason = FileSkipReason::from_scan_error(scan_error);
    let reason_counter = match skip_reason {
        FileSkipReason::NonAbsolutePath => &mut scan_statistics.files_skipped_non_absolute_path,
        FileSkipReason::NotFound => &mut scan_statistics.files_skipped_not_found,
        FileSkipReason::PermissionDenied => &mut scan_statistics.files_skipped_permission_denied,
        FileSkipReason::LineExceedsSkipCap => {
            &mut scan_statistics.files_skipped_line_exceeds_skip_cap
        }
        FileSkipReason::TooManyLines => &mut scan_statistics.files_skipped_too_many_lines,
        FileSkipReason::OtherError => &mut scan_statistics.files_skipped_other_error,
    };
    *reason_counter = reason_counter.saturating_add(1);
    file_notes.skipped_files.push(SkippedFileNote {
        source_file_index: file_index,
        reason: skip_reason,
        error_code: scan_error.code(),
    });
}

/// Checks that the loop-scan bookkeeping is complete and self-consistent.
///
/// # Project context
/// The `[loop-scan coverage]` block promises that no file goes unexplained,
/// and the `[loop-scan file notes]` block promises to name every
/// file behind the non-cold skip counters and the over-long-line counter.
/// This function makes both promises structural: if a later edit adds a skip
/// path but forgets its counter, or updates a counter without listing the
/// file, the run stops with a code instead of printing figures that silently
/// do not add up.
///
/// # Checks (in order; the first failure returns)
/// 1. Totals (code 407): `files_scanned` + every skip counter (including
///    cold) == `files_total`. Every LCOV file is counted in exactly one place.
/// 2. Listing (code 408):
///    - listed skipped files == sum of the six non-cold skip counters
///      (cold files are counted only, never listed), and
///    - listed partly scanned files == `files_with_overlong_source_lines`.
///
/// # Arguments
/// - `statistics`: the counters returned by `scan_all_files_for_loops`.
/// - `file_notes`: the per-file listing returned by `scan_all_files_for_loops`.
///
/// # Returns
/// - `Ok(())` when both checks hold.
/// - `Err(AnaLoopScanTotalsMismatch)`: check 1 failed, or its sum overflowed.
/// - `Err(AnaLoopScanFileNotesMismatch)`: check 2 failed, or its sum overflowed.
///
/// # Modes
/// Both checks are internal invariants (they cannot fail when the code is
/// correct and memory is sound). Debug builds (not test) panic via
/// `debug_assert!`; test and debug builds print the compared values;
/// production-release returns the code only.
fn check_loop_scan_totals(
    statistics: &LoopScanStatistics,
    file_notes: &LoopScanFileNotes,
) -> Result<(), HeatmapError> {
    // ------------------------------------------------------------------
    // Check 1 (code 407): scanned + all skip reasons == files listed in the LCOV.
    // ------------------------------------------------------------------
    let accounted_parts: [usize; 8] = [
        statistics.files_scanned,
        statistics.files_skipped_cold,
        statistics.files_skipped_non_absolute_path,
        statistics.files_skipped_not_found,
        statistics.files_skipped_permission_denied,
        statistics.files_skipped_line_exceeds_skip_cap,
        statistics.files_skipped_too_many_lines,
        statistics.files_skipped_other_error,
    ];
    let mut accounted_files: usize = 0;
    for part in accounted_parts.iter() {
        accounted_files = match accounted_files.checked_add(*part) {
            Some(sum) => sum,
            None => return Err(HeatmapError::AnaLoopScanTotalsMismatch),
        };
    }
    // The summing loop has ended; compare only now, after every part is added.

    // --- Check: scanned + all skip reasons == files listed in the LCOV ---
    // internal invariant: every file is counted in exactly one place.
    if accounted_files != statistics.files_total {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert!(
            false,
            "HIX-{}: accounted {} != listed {}",
            HeatmapError::AnaLoopScanTotalsMismatch.code(),
            accounted_files,
            statistics.files_total
        );
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: accounted {} != listed {}",
            HeatmapError::AnaLoopScanTotalsMismatch.code(),
            accounted_files,
            statistics.files_total
        );
        return Err(HeatmapError::AnaLoopScanTotalsMismatch);
    }

    // ------------------------------------------------------------------
    // Check 2 (code 408): listed files == counted files.
    // ------------------------------------------------------------------
    let non_cold_skip_parts: [usize; 6] = [
        statistics.files_skipped_non_absolute_path,
        statistics.files_skipped_not_found,
        statistics.files_skipped_permission_denied,
        statistics.files_skipped_line_exceeds_skip_cap,
        statistics.files_skipped_too_many_lines,
        statistics.files_skipped_other_error,
    ];
    let mut counted_non_cold_skips: usize = 0;
    for part in non_cold_skip_parts.iter() {
        counted_non_cold_skips = match counted_non_cold_skips.checked_add(*part) {
            Some(sum) => sum,
            None => return Err(HeatmapError::AnaLoopScanFileNotesMismatch),
        };
    }
    // The summing loop has ended; compare only now, after every part is added.

    // --- Check: listed skipped / partly scanned files == their counters ---
    // internal invariant: each counter and its listing are updated together
    // (see `record_skipped_file` and the over-long branch in
    // `scan_all_files_for_loops`).
    let listing_matches = file_notes.skipped_files.len() == counted_non_cold_skips
        && file_notes.partly_scanned_files.len() == statistics.files_with_overlong_source_lines;
    if !listing_matches {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert!(
            false,
            "HIX-{}: listed skips {} vs counted {}; listed partly scanned {} vs counted {}",
            HeatmapError::AnaLoopScanFileNotesMismatch.code(),
            file_notes.skipped_files.len(),
            counted_non_cold_skips,
            file_notes.partly_scanned_files.len(),
            statistics.files_with_overlong_source_lines
        );
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: listed skips {} vs counted {}; listed partly scanned {} vs counted {}",
            HeatmapError::AnaLoopScanFileNotesMismatch.code(),
            file_notes.skipped_files.len(),
            counted_non_cold_skips,
            file_notes.partly_scanned_files.len(),
            statistics.files_with_overlong_source_lines
        );
        return Err(HeatmapError::AnaLoopScanFileNotesMismatch);
    }

    Ok(())
}

/// Opens one source file (Tier-1 retry) and scans it.
fn scan_one_source_file(
    absolute_source_path: &AbsolutePath,
    file_index: usize,
    record: &FileCoverageRecord,
) -> Result<SourceScanOutcome, HeatmapError> {
    let source_path = absolute_source_path.ap_get()?;
    let source_file = open_file_with_retry(
        source_path,
        FileOpenPurpose::ReadExisting,
        SOURCE_OPEN_ERROR_CODES,
    )?;
    let mut source_reader = BufReader::new(source_file);
    scan_source_reader(&mut source_reader, file_index, record)
}

/// Scans one source file line by line for loop headers and builds LOOP sites.
///
/// # Project context
/// LLVM coverage has no "loop" concept, only per-line counts. This scan is
/// the lightweight (no AST) bridge: it finds lines that start a loop, and
/// takes that line's LCOV `DA` count as the loop's count. That count
/// approximates the number of iterations, which is what makes a loop hot
/// even inside a rarely called function.
///
/// # Per line
/// 1. Read the line with `read_source_line_skipping_overlong`. An over-long
///    line (more than `MAX_LINE_BYTES`) is counted in `overlong_lines_found`;
///    its kept start is then handled exactly like a normal line, so a loop
///    header at the start of a very long line is still found.
/// 2. Skip comment lines (`//` lines; `/* ... */` blocks that start a line).
///    For over-long lines, a `*/` in the discarded part also counts as the
///    end of the comment.
/// 3. Detect `for` / `while` / `loop` (optionally labeled) at line start.
/// 4. Look up the line's `DA` count. If there is none (not instrumented,
///    cfg'd out, or a lexical false positive), the header is counted in
///    `loop_headers_without_line_data` and skipped.
/// 5. Attribute the loop to the nearest preceding function definition line
///    (see `find_enclosing_function`). Store that function's summed entry
///    count, which the report uses for "iterations per call".
///
/// Line numbers stay exact: every line counts as one line, over-long or not.
///
/// # Arguments
/// - `source_reader`: buffered source text (a file in production, a `Cursor` in tests).
/// - `file_index`: index of `record` in the records slice (stored in each site).
/// - `record`: this file's LCOV data (function definitions, line counts).
///
/// # Returns
/// - `Ok(SourceScanOutcome)`: loop sites plus transparency counters.
/// - `Err(SrcReadFailed | SrcLineExceedsSkipCap | SrcSkipReadFailed |
///   SrcSkipReadCallLimit | SrcTooManyLines | SrcLineNumberOverflow |
///   AnaFunctionLineIndexOverflow | TypeLineNumberZero)`. The caller
///   (`scan_all_files_for_loops`) absorbs these at Tier 2: the file is
///   skipped, the reason is counted, and the analysis continues.
fn scan_source_reader<R: BufRead>(
    source_reader: &mut R,
    file_index: usize,
    record: &FileCoverageRecord,
) -> Result<SourceScanOutcome, HeatmapError> {
    let function_line_index = build_function_line_index(record)?;

    let mut scan_outcome = SourceScanOutcome::default();
    let mut line_buffer: Vec<u8> = Vec::with_capacity(256);
    let mut inside_block_comment = false;

    for line_index in 0..MAX_SOURCE_LINES_PER_FILE {
        let read_outcome = read_source_line_skipping_overlong(
            source_reader,
            &mut line_buffer,
            MAX_SKIPPED_LINE_BYTES,
        )?;
        // For complete lines nothing was discarded, so this is false.
        let discarded_part_contains_block_comment_end = match read_outcome {
            SourceLineReadOutcome::EndOfInput => return Ok(scan_outcome),
            SourceLineReadOutcome::CompleteLine => false,
            SourceLineReadOutcome::OverLongLineStartKept {
                discarded_part_contains_block_comment_end,
            } => {
                scan_outcome.overlong_lines_found =
                    scan_outcome.overlong_lines_found.saturating_add(1);
                discarded_part_contains_block_comment_end
            }
        };
        let trimmed_line = trim_ascii_whitespace_start(&line_buffer);

        // Crude comment handling (documented limitation: `/*` must start a line).
        if inside_block_comment {
            if contains_block_comment_end(trimmed_line) || discarded_part_contains_block_comment_end
            {
                inside_block_comment = false;
            }
            continue;
        }
        if trimmed_line.starts_with(b"//") {
            continue;
        }
        if trimmed_line.starts_with(b"/*") {
            let after_opener = trimmed_line.get(2..).unwrap_or(&[]);
            if !(contains_block_comment_end(after_opener)
                || discarded_part_contains_block_comment_end)
            {
                inside_block_comment = true;
            }
            continue;
        }

        let loop_keyword = match detect_loop_keyword(trimmed_line) {
            Some(keyword) => keyword,
            None => continue,
        };
        scan_outcome.loop_headers_found = scan_outcome.loop_headers_found.saturating_add(1);

        let one_based_line = match line_index.checked_add(1) {
            Some(value) => value,
            None => return Err(HeatmapError::SrcLineNumberOverflow),
        };
        let line_value = match u32::try_from(one_based_line) {
            Ok(value) => value,
            Err(_conversion_error) => return Err(HeatmapError::SrcLineNumberOverflow),
        };
        let line_number = SourceLineNumber::sln_new(line_value)?;

        let header_line_count = match record.line_execution_counts.get(&line_number) {
            Some(&count) => count,
            None => {
                scan_outcome.loop_headers_without_line_data = scan_outcome
                    .loop_headers_without_line_data
                    .saturating_add(1);
                continue;
            }
        };

        let (enclosing_function_name, enclosing_function_entry_count) =
            match find_enclosing_function(&function_line_index, line_number) {
                Some(entry) => (entry.function_name, Some(entry.summed_entry_count)),
                None => ("<no enclosing fn found>", None),
            };

        let mut loop_display_name =
            String::with_capacity(enclosing_function_name.len().saturating_add(16));
        loop_display_name.push_str(loop_keyword.as_label());
        loop_display_name.push_str(" loop in ");
        loop_display_name.push_str(enclosing_function_name);

        scan_outcome.loop_sites.push(HeatSite {
            source_file_index: file_index,
            line_number,
            display_name: loop_display_name,
            execution_count: header_line_count,
            merged_instance_count: 1,
            enclosing_function_entry_count,
        });
    }
    Err(HeatmapError::SrcTooManyLines)
}

/// One function definition line in one source file, used only to attribute
/// loops to their enclosing function.
///
/// Entry counts of all LCOV instances at the same line are summed, which is
/// the same merge rule as function sites, so the per-call ratio uses the same
/// denominator the FUNCTIONS section shows. `function_name` borrows from the
/// `FileCoverageRecord`; the index lives only for the duration of one file scan.
#[derive(Debug, Clone, Copy)]
struct FunctionLineEntry<'name> {
    line_number: SourceLineNumber,
    function_name: &'name str,
    summed_entry_count: u64,
}

/// Builds the sorted, same-line-merged function index for one source file.
///
/// # Steps
/// 1. One entry per `FN` definition, with that instance's `FNDA` count
///    (0 if the instance has no `FNDA` entry).
/// 2. Sort by line number (required by the binary search in
///    `find_enclosing_function`).
/// 3. Merge adjacent entries on the same line by summing counts (generics).
///
/// # Arguments
/// - `record`: one file's LCOV data.
///
/// # Returns
/// - `Ok(entries)`: sorted ascending by line, one entry per distinct line.
/// - `Err(HeatmapError::AnaFunctionLineIndexOverflow)`: summed count exceeded u64.
fn build_function_line_index(
    record: &FileCoverageRecord,
) -> Result<Vec<FunctionLineEntry<'_>>, HeatmapError> {
    let mut unmerged_entries: Vec<FunctionLineEntry<'_>> = record
        .function_definitions
        .iter()
        .map(|(line_number, function_name)| FunctionLineEntry {
            line_number: *line_number,
            function_name: function_name.as_str(),
            summed_entry_count: record
                .function_entry_counts
                .get(function_name)
                .copied()
                .unwrap_or(0),
        })
        .collect();
    unmerged_entries.sort_by_key(|entry| entry.line_number);

    let mut merged_entries: Vec<FunctionLineEntry<'_>> = Vec::with_capacity(unmerged_entries.len());
    for entry in unmerged_entries {
        let same_line_as_last = merged_entries
            .last()
            .map(|last_entry| last_entry.line_number == entry.line_number)
            .unwrap_or(false);
        if same_line_as_last {
            if let Some(last_entry) = merged_entries.last_mut() {
                last_entry.summed_entry_count = match last_entry
                    .summed_entry_count
                    .checked_add(entry.summed_entry_count)
                {
                    Some(sum) => sum,
                    None => return Err(HeatmapError::AnaFunctionLineIndexOverflow),
                };
            }
        } else {
            merged_entries.push(entry);
        }
    }
    Ok(merged_entries)
}

/// Returns the function whose definition line is the nearest at or before
/// `line_number`, which is taken as the function enclosing that line.
///
/// # Approximation (documented limitation)
/// Without an AST there are no function end-lines, so "nearest preceding
/// definition" is used. This is usually right. It can be wrong for a loop
/// placed after a nested fn or closure that ends before the loop, in which
/// case the loop is attributed to that inner fn. The report flags the most
/// visible symptom: a counted loop whose attributed function has count 0
/// ("attribution suspect").
///
/// # Arguments
/// - `sorted_function_lines`: output of `build_function_line_index` (ascending).
/// - `line_number`: the loop header's line.
///
/// # Returns
/// - `Some(entry)`: a copy of the enclosing entry.
/// - `None`: no function is defined at or before this line (e.g. a loop in a
///   `const`/`static` initializer, or a lexical false positive near the top).
fn find_enclosing_function<'name>(
    sorted_function_lines: &[FunctionLineEntry<'name>],
    line_number: SourceLineNumber,
) -> Option<FunctionLineEntry<'name>> {
    let insertion_point =
        sorted_function_lines.partition_point(|entry| entry.line_number <= line_number);
    insertion_point
        .checked_sub(1)
        .and_then(|index| sorted_function_lines.get(index))
        .copied()
}

/// Detects a loop header at the start of an already left-trimmed line.
/// Accepts optional label (`'outer: for ...`). Rejects `for<'a>`, `forward`, `loopy`.
fn detect_loop_keyword(trimmed_line: &[u8]) -> Option<LoopKeyword> {
    let candidate_text = strip_loop_label(trimmed_line);
    if line_starts_with_keyword(candidate_text, b"for") {
        return Some(LoopKeyword::For);
    }
    if line_starts_with_keyword(candidate_text, b"while") {
        return Some(LoopKeyword::While);
    }
    if line_starts_with_keyword(candidate_text, b"loop") {
        return Some(LoopKeyword::Loop);
    }
    None
}

/// True if `text` starts with `keyword` followed by whitespace, end of text,
/// or (for `loop` only) an opening brace.
fn line_starts_with_keyword(text: &[u8], keyword: &[u8]) -> bool {
    if !text.starts_with(keyword) {
        return false;
    }
    match text.get(keyword.len()) {
        None => true,
        Some(&next_byte) => {
            next_byte.is_ascii_whitespace() || (keyword == b"loop" && next_byte == b'{')
        }
    }
}

/// Removes a leading loop label such as `'outer:` (and following whitespace).
/// Returns the input unchanged if no well-formed label is present.
fn strip_loop_label(text: &[u8]) -> &[u8] {
    if text.first() != Some(&b'\'') {
        return text;
    }
    let label_length = text
        .iter()
        .skip(1)
        .take_while(|byte| byte.is_ascii_alphanumeric() || **byte == b'_')
        .count();
    if label_length == 0 {
        return text;
    }
    let colon_index = match label_length.checked_add(1) {
        Some(index) => index,
        None => return text,
    };
    if text.get(colon_index) != Some(&b':') {
        return text;
    }
    let after_colon_index = match colon_index.checked_add(1) {
        Some(index) => index,
        None => return text,
    };
    match text.get(after_colon_index..) {
        Some(rest) => trim_ascii_whitespace_start(rest),
        None => text,
    }
}

/// Left-trims ASCII whitespace from a byte slice.
fn trim_ascii_whitespace_start(text: &[u8]) -> &[u8] {
    let first_non_whitespace = text
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(text.len());
    text.get(first_non_whitespace..).unwrap_or(&[])
}

/// True if the slice contains `*/`.
fn contains_block_comment_end(text: &[u8]) -> bool {
    text.windows(2).any(|window| window == b"*/")
}

// ============================================================================
// Ranking & summary
// ============================================================================

/// Sorts hottest first; deterministic tie-break by file index, then line.
fn sort_sites_hottest_first(sites: &mut [HeatSite]) {
    sites.sort_by(|left_site, right_site| {
        right_site
            .execution_count
            .cmp(&left_site.execution_count)
            .then_with(|| {
                left_site
                    .source_file_index
                    .cmp(&right_site.source_file_index)
            })
            .then_with(|| left_site.line_number.cmp(&right_site.line_number))
    });
}

/// Sorts one kind of site hottest-first, then summarizes it — always in that order.
///
/// # Project context
/// `summarize_sorted_sites` requires hottest-first input. Its concentration
/// figures ("the hottest K sites carry 50% / 90% / 99% of all counts") walk
/// the list from the top and record the first position where each threshold
/// is crossed. On unsorted input those figures are silently wrong: no error,
/// no panic, just misleading numbers in the report.
///
/// This function exists so that no caller can summarize without sorting.
/// (A test call path lost its sort during an edit; this closes that gap.)
///
/// # Arguments
/// - `sites`: all function sites, or all loop sites (one kind only; counts of
///   different kinds have different units and must not be mixed). The slice
///   is reordered in place; afterwards it is hottest-first with a
///   deterministic tie-break (file index, then line number).
///
/// # Returns
/// - `Ok(HeatKindSummary)` describing the now-sorted `sites`.
/// - `Err(HeatmapError::AnaCountOverflow)` or
///   `Err(HeatmapError::AnaHistogramIndexInvalid)`, propagated unchanged from
///   `summarize_sorted_sites`. Codes are unique, so `?` does not obscure the cause.
///
/// # Modes
/// No mode-specific behavior; both callees are panic-free.
fn sort_and_summarize_sites(sites: &mut [HeatSite]) -> Result<HeatKindSummary, HeatmapError> {
    sort_sites_hottest_first(sites);
    summarize_sorted_sites(sites)
}

/// Computes totals, zero-count sites, concentration, and decade histogram.
/// `sorted_sites` must be sorted hottest first.
fn summarize_sorted_sites(sorted_sites: &[HeatSite]) -> Result<HeatKindSummary, HeatmapError> {
    let mut summary = HeatKindSummary {
        site_count: sorted_sites.len(),
        zero_count_sites: 0,
        total_count: 0,
        sites_reaching_percent: [0; CONCENTRATION_TARGET_COUNT],
        decade_histogram: [0; DECADE_BUCKET_COUNT],
    };

    for site in sorted_sites.iter() {
        summary.total_count = match summary
            .total_count
            .checked_add(u128::from(site.execution_count))
        {
            Some(sum) => sum,
            None => return Err(HeatmapError::AnaCountOverflow),
        };
        if site.execution_count == 0 {
            summary.zero_count_sites = summary.zero_count_sites.saturating_add(1);
        }
        let bucket_index = match site.execution_count.checked_ilog10() {
            None => 0,
            Some(decimal_log) => (decimal_log as usize).saturating_add(1),
        };
        match summary.decade_histogram.get_mut(bucket_index) {
            Some(bucket_slot) => *bucket_slot = bucket_slot.saturating_add(1),
            None => return Err(HeatmapError::AnaHistogramIndexInvalid),
        }
    }

    if summary.total_count == 0 {
        return Ok(summary); // concentration is "n/a" (left as 0)
    }

    // threshold_i = total * target_percent_i (compare against cumulative * 100).
    let mut scaled_thresholds: [u128; CONCENTRATION_TARGET_COUNT] = [0; CONCENTRATION_TARGET_COUNT];
    for (target_index, target_percent) in CONCENTRATION_TARGETS_PERCENT.iter().enumerate() {
        let threshold = match summary.total_count.checked_mul(*target_percent) {
            Some(value) => value,
            None => return Err(HeatmapError::AnaCountOverflow),
        };
        if let Some(threshold_slot) = scaled_thresholds.get_mut(target_index) {
            *threshold_slot = threshold;
        }
    }

    let mut cumulative_count: u128 = 0;
    for (site_index, site) in sorted_sites.iter().enumerate() {
        cumulative_count = match cumulative_count.checked_add(u128::from(site.execution_count)) {
            Some(sum) => sum,
            None => return Err(HeatmapError::AnaCountOverflow),
        };
        let scaled_cumulative = match cumulative_count.checked_mul(100) {
            Some(value) => value,
            None => return Err(HeatmapError::AnaCountOverflow),
        };
        for (target_index, threshold) in scaled_thresholds.iter().enumerate() {
            if let Some(reached_slot) = summary.sites_reaching_percent.get_mut(target_index) {
                if *reached_slot == 0 && scaled_cumulative >= *threshold {
                    *reached_slot = site_index.saturating_add(1);
                }
            }
        }
    }
    Ok(summary)
}

/// Percent of `part` in `total` (0.0 when total is 0). Floating point: no panic.
fn percent_of_total(part: u64, total: u128) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (part as f64) * 100.0 / (total as f64)
}

/// Percent of `part` sites in `whole` sites (0.0 when whole is 0).
fn percent_of_site_count(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64) * 100.0 / (whole as f64)
}

/// Computes the descriptive distribution-shape figures for one kind of site.
///
/// # Project context
/// Concentration ("the hottest K sites carry P%") says how top-heavy counts
/// are. The shape figures add how the counts are spread: evenly or in
/// separated clusters, and whether the head falls off a cliff between two
/// adjacent ranks. They help compare runs and programs; they are descriptive
/// only (marked experimental in the report).
///
/// # Definitions
/// - Gini, with sites in ascending order x_1..x_n (i = 1..n) and total T:
///   `G = 2 * sum(i * x_i) / (n * T) - (n + 1) / n`. Computed over all sites,
///   and over sites with count > 0. Clamped to [0, 1] against float rounding.
/// - Top shares: percent of T carried by the hottest `TOP_SHARE_NARROW_SITES`
///   and `TOP_SHARE_WIDE_SITES` sites.
/// - Empty-decade gap: see `find_largest_empty_decade_gap`.
/// - Head drop: see `find_largest_head_drop`; the head is the sites that
///   carry the last concentration target (e.g. 99%) of counts.
///
/// # Arguments
/// - `sorted_sites`: one kind's sites, hottest-first (checked here).
/// - `summary`: that kind's summary from `summarize_sorted_sites`.
///
/// # Returns
/// - `Ok(DistributionShape)`.
/// - `Err(AnaShapeInputNotSorted)`: input not hottest-first (internal invariant).
/// - `Err(AnaShapeSumOverflow)`: a u128 sum overflowed (not reachable within
///   the `MAX_COVERAGE_ENTRIES` input bound; checked anyway).
fn compute_distribution_shape(
    sorted_sites: &[HeatSite],
    summary: &HeatKindSummary,
) -> Result<DistributionShape, HeatmapError> {
    // --- Check: sites are sorted hottest-first ---
    // internal invariant: callers pass the output of `sort_and_summarize_sites`.
    let out_of_order = sorted_sites.windows(2).any(
        |pair| matches!(pair, [higher, lower] if higher.execution_count < lower.execution_count),
    );
    if out_of_order {
        #[cfg(all(debug_assertions, not(test)))]
        debug_assert!(
            false,
            "HIX-{}: distribution-shape input not sorted hottest-first",
            HeatmapError::AnaShapeInputNotSorted.code()
        );
        #[cfg(debug_assertions)]
        eprintln!(
            "HIX-{}: distribution-shape input not sorted hottest-first",
            HeatmapError::AnaShapeInputNotSorted.code()
        );
        return Err(HeatmapError::AnaShapeInputNotSorted);
    }

    let site_count = sorted_sites.len();
    // Sorted hottest-first, so every counted site comes before every zero site.
    let counted_site_count = sorted_sites
        .iter()
        .filter(|site| site.execution_count > 0)
        .count();

    let mut total_count: u128 = 0;
    let mut weighted_sum_all_sites: u128 = 0;
    let mut weighted_sum_counted_sites: u128 = 0;
    let mut top_narrow_count: u128 = 0;
    let mut top_wide_count: u128 = 0;

    for (position, site) in sorted_sites.iter().enumerate() {
        let count = u128::from(site.execution_count);
        total_count = match total_count.checked_add(count) {
            Some(sum) => sum,
            None => return Err(HeatmapError::AnaShapeSumOverflow),
        };
        if position < TOP_SHARE_NARROW_SITES {
            top_narrow_count = match top_narrow_count.checked_add(count) {
                Some(sum) => sum,
                None => return Err(HeatmapError::AnaShapeSumOverflow),
            };
        }
        if position < TOP_SHARE_WIDE_SITES {
            top_wide_count = match top_wide_count.checked_add(count) {
                Some(sum) => sum,
                None => return Err(HeatmapError::AnaShapeSumOverflow),
            };
        }
        if count == 0 {
            continue;
        }
        // Ascending rank i (1 = coldest) from hottest-first position.
        let ascending_rank_all = site_count.saturating_sub(position) as u128;
        let ascending_rank_counted = counted_site_count.saturating_sub(position) as u128;
        let weighted_all = match ascending_rank_all.checked_mul(count) {
            Some(product) => product,
            None => return Err(HeatmapError::AnaShapeSumOverflow),
        };
        let weighted_counted = match ascending_rank_counted.checked_mul(count) {
            Some(product) => product,
            None => return Err(HeatmapError::AnaShapeSumOverflow),
        };
        weighted_sum_all_sites = match weighted_sum_all_sites.checked_add(weighted_all) {
            Some(sum) => sum,
            None => return Err(HeatmapError::AnaShapeSumOverflow),
        };
        weighted_sum_counted_sites = match weighted_sum_counted_sites.checked_add(weighted_counted)
        {
            Some(sum) => sum,
            None => return Err(HeatmapError::AnaShapeSumOverflow),
        };
    }

    let last_target_index = CONCENTRATION_TARGET_COUNT.saturating_sub(1);
    let head_site_count = summary
        .sites_reaching_percent
        .get(last_target_index)
        .copied()
        .unwrap_or(0);

    Ok(DistributionShape {
        gini_all_sites: gini_from_weighted_sum(weighted_sum_all_sites, total_count, site_count),
        gini_counted_sites: gini_from_weighted_sum(
            weighted_sum_counted_sites,
            total_count,
            counted_site_count,
        ),
        top_narrow_share_percent: share_of_total_percent(top_narrow_count, total_count),
        top_wide_share_percent: share_of_total_percent(top_wide_count, total_count),
        largest_empty_decade_gap: find_largest_empty_decade_gap(&summary.decade_histogram),
        largest_head_drop: find_largest_head_drop(sorted_sites, head_site_count),
    })
}

/// Gini from `sum(i * x_i)` (ascending ranks), the total, and the site count.
/// `None` when the total or the site count is 0. Clamped to [0, 1].
fn gini_from_weighted_sum(weighted_sum: u128, total_count: u128, site_count: usize) -> Option<f64> {
    if total_count == 0 || site_count == 0 {
        return None;
    }
    let site_count_float = site_count as f64;
    let gini = (2.0 * (weighted_sum as f64)) / (site_count_float * (total_count as f64))
        - (site_count_float + 1.0) / site_count_float;
    Some(gini.max(0.0).min(1.0))
}

/// Percent of `part` in `total`; `None` when the total is 0.
fn share_of_total_percent(part: u128, total_count: u128) -> Option<f64> {
    if total_count == 0 {
        return None;
    }
    Some((part as f64) * 100.0 / (total_count as f64))
}

/// Finds the longest run of empty decade buckets between two occupied ones.
///
/// Only buckets 1..=20 (counts >= 1) are considered; bucket 0 (count = 0)
/// is not an order of magnitude. Empty buckets below the lowest or above the
/// highest occupied bucket are not gaps. On ties the lowest gap is kept.
///
/// # Returns
/// `Some(EmptyDecadeGap)` for the largest gap, or `None` if there is no gap.
fn find_largest_empty_decade_gap(
    decade_histogram: &[u64; DECADE_BUCKET_COUNT],
) -> Option<EmptyDecadeGap> {
    let mut previous_occupied_bucket: Option<usize> = None;
    let mut largest_gap: Option<EmptyDecadeGap> = None;
    for (bucket_index, bucket_site_count) in decade_histogram.iter().enumerate().skip(1) {
        if *bucket_site_count == 0 {
            continue;
        }
        if let Some(previous_bucket) = previous_occupied_bucket {
            let empty_decade_count = bucket_index
                .saturating_sub(previous_bucket)
                .saturating_sub(1);
            let is_larger = empty_decade_count > 0
                && largest_gap
                    .map(|gap| empty_decade_count > gap.empty_decade_count)
                    .unwrap_or(true);
            if is_larger {
                largest_gap = Some(EmptyDecadeGap {
                    empty_decade_count,
                    lower_bucket_index: previous_bucket,
                    upper_bucket_index: bucket_index,
                });
            }
        }
        previous_occupied_bucket = Some(bucket_index);
    }
    largest_gap
}

/// Finds the largest count ratio between adjacent ranks within the head
/// (the first `head_site_count` sites of a hottest-first list).
///
/// Pairs whose lower count is 0 are skipped (the ratio is undefined; zero
/// sites are reported separately). Only ratios > 1.0 count as drops. On ties
/// the hottest pair is kept.
///
/// # Returns
/// `Some(HeadRankDrop)`, or `None` if the head has fewer than 2 sites or no drop.
fn find_largest_head_drop(
    sorted_sites: &[HeatSite],
    head_site_count: usize,
) -> Option<HeadRankDrop> {
    let head_length = head_site_count.min(sorted_sites.len());
    let head_sites = sorted_sites.get(..head_length).unwrap_or(&[]);
    let mut largest_drop: Option<HeadRankDrop> = None;
    for (higher_position, pair) in head_sites.windows(2).enumerate() {
        if let [higher_site, lower_site] = pair {
            if lower_site.execution_count == 0 {
                continue;
            }
            let drop_ratio =
                (higher_site.execution_count as f64) / (lower_site.execution_count as f64);
            let is_larger = drop_ratio > 1.0
                && largest_drop
                    .map(|drop| drop_ratio > drop.drop_ratio)
                    .unwrap_or(true);
            if is_larger {
                largest_drop = Some(HeadRankDrop {
                    higher_position,
                    drop_ratio,
                });
            }
        }
    }
    largest_drop
}

// ============================================================================
// Reports
// ============================================================================

/// Maps an in-memory report write failure to its code (debug detail only).
fn report_buffer_write_error(_io_error: std::io::Error) -> HeatmapError {
    #[cfg(debug_assertions)]
    eprintln!(
        "HIX-{}: report buffer write failed: {}",
        HeatmapError::RptBufferWriteFailed.code(),
        _io_error
    );
    HeatmapError::RptBufferWriteFailed
}

/// Resolves a site's file index to its source path text.
fn lookup_source_path(
    records: &[FileCoverageRecord],
    file_index: usize,
) -> Result<&str, HeatmapError> {
    match records.get(file_index) {
        Some(record) => Ok(record.source_path_text.as_str()),
        None => {
            #[cfg(all(debug_assertions, not(test)))]
            debug_assert!(
                false,
                "HIX-{}: file index {} invalid",
                HeatmapError::AnaFileIndexInvalid.code(),
                file_index
            );
            #[cfg(debug_assertions)]
            eprintln!(
                "HIX-{}: file index {} invalid",
                HeatmapError::AnaFileIndexInvalid.code(),
                file_index
            );
            Err(HeatmapError::AnaFileIndexInvalid)
        }
    }
}

/// Writes the `[loop-scan file notes]` section: which files were skipped
/// (and why), and which were only partly scanned.
///
/// # Project context
/// `[loop-scan coverage]` gives counts; this section names the files behind
/// them, so a reader can see exactly where loop data is missing or partial.
/// Cold files are counted only (they cannot contain hot loops), never listed.
/// Each list shows its full total, then at most `top_n_limit` rows.
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed | AnaFileIndexInvalid)`.
fn write_loop_scan_file_notes<W: Write>(
    report_writer: &mut W,
    inputs: &ReportInputs,
) -> Result<(), HeatmapError> {
    let file_notes = inputs.loop_scan_file_notes;
    writeln!(
        report_writer,
        "[loop-scan file notes]  (cold files are counted above, not listed)"
    )
    .map_err(report_buffer_write_error)?;

    writeln!(
        report_writer,
        "  skipped files (not scanned; their loops are missing): {}   (showing up to {})",
        file_notes.skipped_files.len(),
        inputs.top_n_limit
    )
    .map_err(report_buffer_write_error)?;
    for note in file_notes.skipped_files.iter().take(inputs.top_n_limit) {
        let source_path_text = lookup_source_path(inputs.records, note.source_file_index)?;
        writeln!(
            report_writer,
            "    {:<30}  code {:>3}  {}",
            note.reason.as_label(),
            note.error_code,
            source_path_text
        )
        .map_err(report_buffer_write_error)?;
    }

    writeln!(
        report_writer,
        "  partly scanned files (over-long lines: start scanned, rest skipped): {}   (showing up to {})",
        file_notes.partly_scanned_files.len(),
        inputs.top_n_limit
    )
    .map_err(report_buffer_write_error)?;
    for note in file_notes
        .partly_scanned_files
        .iter()
        .take(inputs.top_n_limit)
    {
        let source_path_text = lookup_source_path(inputs.records, note.source_file_index)?;
        writeln!(
            report_writer,
            "    {:>6} over-long lines  {}",
            note.overlong_line_count, source_path_text
        )
        .map_err(report_buffer_write_error)?;
    }
    Ok(())
}

/// Writes the run-metadata lines of `[provenance]`.
///
/// Every line is always present (`(not given)` when absent), so reports have
/// a fixed layout. Work units per minute is shown only when both duration and
/// work units were given (both are >= 1 by type, so no division by zero).
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed)`, or a `Type*Corrupted` code from a `.get()` recheck.
fn write_run_metadata_provenance<W: Write>(
    report_writer: &mut W,
    run_metadata: &RunMetadata,
) -> Result<(), HeatmapError> {
    match &run_metadata.run_label {
        Some(run_label) => writeln!(
            report_writer,
            "  run label               : {}",
            run_label.rl_get()?
        ),
        None => writeln!(report_writer, "  run label               : (not given)"),
    }
    .map_err(report_buffer_write_error)?;

    let duration_seconds = match &run_metadata.run_duration {
        Some(run_duration) => Some(run_duration.rds_get()?),
        None => None,
    };
    match duration_seconds {
        Some(seconds) => writeln!(
            report_writer,
            "  run duration            : {} s ({:.2} min)",
            seconds,
            (seconds as f64) / 60.0
        ),
        None => writeln!(report_writer, "  run duration            : (not given)"),
    }
    .map_err(report_buffer_write_error)?;

    let work_unit_values = match &run_metadata.work_units {
        Some(work_units) => Some((work_units.count.wuc_get()?, work_units.name.wun_get()?)),
        None => None,
    };
    match work_unit_values {
        Some((unit_count, unit_name)) => writeln!(
            report_writer,
            "  work units              : {} {}",
            unit_count, unit_name
        ),
        None => writeln!(report_writer, "  work units              : (not given)"),
    }
    .map_err(report_buffer_write_error)?;

    match (duration_seconds, work_unit_values) {
        (Some(seconds), Some((unit_count, unit_name))) => writeln!(
            report_writer,
            "  work units per minute   : {:.2} {}/min",
            (unit_count as f64) * 60.0 / (seconds as f64),
            unit_name
        ),
        _ => writeln!(
            report_writer,
            "  work units per minute   : n/a (needs --run-duration-secs and --work-units)"
        ),
    }
    .map_err(report_buffer_write_error)?;
    Ok(())
}

/// Writes the human-readable text report.
///
/// # Project context
/// The report is meant to be read by a person deciding where to look in a
/// large codebase. It therefore starts with provenance (what was measured,
/// how, and what was left out) before any numbers, so every figure can be
/// traced back to its method and its known limitations.
///
/// # Sections, in order
/// 1. Title.
/// 2. `[provenance]`: input and output paths, run metadata, measurement
///    method, meaning of each count, loop-detection method, over-long-line
///    handling, and integrity counters.
/// 3. `[loop-scan coverage]`: every LCOV source file counted as scanned or
///    under exactly one skip reason, plus over-long-line and loop-header counters.
/// 4. `[loop-scan file notes]`: the skipped and partly scanned files by name.
/// 5. `[FUNCTIONS]` and `[LOOPS]` (see `write_heat_kind_section`).
/// 6. `[DISTRIBUTION SHAPE]`, experimental (see `write_distribution_shape_section`).
/// 7. `[CO-COUNT GROUPS]` (see `write_co_count_groups`).
///
/// # Arguments
/// - `report_writer`: in-memory report buffer.
/// - `inputs`: all report data.
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed)`, or an error code propagated from a section writer.
fn write_text_report<W: Write>(
    report_writer: &mut W,
    inputs: &ReportInputs,
) -> Result<(), HeatmapError> {
    let stats = inputs.loop_scan_statistics;
    writeln!(
        report_writer,
        "hix_heatmap_indices_for_compute :: count-heat report"
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "==============================================="
    )
    .map_err(report_buffer_write_error)?;
    writeln!(report_writer).map_err(report_buffer_write_error)?;
    writeln!(report_writer, "[provenance: what was measured, and how]")
        .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  input lcov file         : {}",
        inputs.lcov_input_path.display()
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  report text file        : {}",
        inputs.report_file_path.display()
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  all-sites tsv file      : {}",
        inputs.sites_tsv_file_path.display()
    )
    .map_err(report_buffer_write_error)?;
    write_run_metadata_provenance(report_writer, inputs.run_metadata)?;
    writeln!(report_writer, "  measurement method      : LLVM source-based coverage counters (rustc -C instrument-coverage); exact counts, not samples").map_err(report_buffer_write_error)?;
    writeln!(report_writer, "  run stop condition      : D = whenever the instrumented program exited cleanly (no in-tool cap)").map_err(report_buffer_write_error)?;
    writeln!(report_writer, "  function count meaning  : entry count (LCOV FNDA); monomorphized instances at one source line are summed").map_err(report_buffer_write_error)?;
    writeln!(report_writer, "  loop count meaning      : loop-header line execution count (LCOV DA); approximately the iteration count").map_err(report_buffer_write_error)?;
    writeln!(report_writer, "  per-call ratio meaning  : loop count / summed entry count of nearest preceding fn definition (approximate)").map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  loop detection method   : lexical line scan for for/while/loop at line start (no AST)"
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
            report_writer,
            "  over-long source lines  : first MAX_LINE_BYTES ({} bytes) scanned like a normal line; rest read and discarded (not an error)",
            MAX_LINE_BYTES
        )
        .map_err(report_buffer_write_error)?;
    writeln!(report_writer, "  time-heat               : ...")
        .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  source files in lcov    : {}",
        inputs.records.len()
    )
    .map_err(report_buffer_write_error)?;
    writeln!(report_writer, "  duplicate FN names      : {}  (expected 0; nonzero = names collapsed before parsing, function counts may be double-counted)", inputs.duplicate_function_name_count).map_err(report_buffer_write_error)?;
    writeln!(report_writer, "  duplicate SF paths      : {}  (expected 0; nonzero = one source file listed more than once, its sites appear more than once)", inputs.duplicate_source_path_count).map_err(report_buffer_write_error)?;
    writeln!(report_writer).map_err(report_buffer_write_error)?;

    writeln!(report_writer, "[loop-scan coverage]").map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files listed in lcov", stats.files_total
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files scanned", stats.files_scanned
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files skipped: cold (every line count = 0)", stats.files_skipped_cold
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files skipped: path not absolute", stats.files_skipped_non_absolute_path
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files skipped: not found", stats.files_skipped_not_found
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files skipped: permission denied", stats.files_skipped_permission_denied
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files skipped: line > MAX_SKIPPED_LINE_BYTES", stats.files_skipped_line_exceeds_skip_cap
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files skipped: too many lines", stats.files_skipped_too_many_lines
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files skipped: other error", stats.files_skipped_other_error
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "files with over-long lines (> MAX_LINE_BYTES)", stats.files_with_overlong_source_lines
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "over-long lines: start scanned, rest skipped", stats.overlong_source_lines_total
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "loop headers found", stats.loop_headers_found
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:<46}: {}",
        "loop headers with no line count", stats.loop_headers_without_line_data
    )
    .map_err(report_buffer_write_error)?;
    writeln!(report_writer).map_err(report_buffer_write_error)?;

    write_loop_scan_file_notes(report_writer, inputs)?;
    writeln!(report_writer).map_err(report_buffer_write_error)?;

    write_heat_kind_section(
        report_writer,
        "FUNCTIONS",
        "calls",
        inputs.function_sites,
        inputs.function_summary,
        inputs.records,
        inputs.top_n_limit,
    )?;
    writeln!(report_writer).map_err(report_buffer_write_error)?;
    write_heat_kind_section(
        report_writer,
        "LOOPS",
        "header-line executions",
        inputs.loop_sites,
        inputs.loop_summary,
        inputs.records,
        inputs.top_n_limit,
    )?;
    writeln!(report_writer).map_err(report_buffer_write_error)?;
    write_distribution_shape_section(report_writer, inputs)?;
    writeln!(report_writer).map_err(report_buffer_write_error)?;
    write_co_count_groups(report_writer, inputs)?;
    Ok(())
}

/// Writes one section (functions or loops): summary, concentration, cold
/// tail, order-of-magnitude histogram, and the Top-N table.
fn write_heat_kind_section<W: Write>(
    report_writer: &mut W,
    section_title: &str,
    count_unit: &str,
    sorted_sites: &[HeatSite],
    summary: &HeatKindSummary,
    records: &[FileCoverageRecord],
    top_n_limit: usize,
) -> Result<(), HeatmapError> {
    writeln!(
        report_writer,
        "[{}]  (count unit: {})",
        section_title, count_unit
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  sites: {}   total: {}   zero-count sites: {} ({:.2}%)",
        summary.site_count,
        summary.total_count,
        summary.zero_count_sites,
        percent_of_site_count(summary.zero_count_sites, summary.site_count)
    )
    .map_err(report_buffer_write_error)?;

    if summary.total_count == 0 {
        writeln!(report_writer, "  concentration: n/a (total count is 0)")
            .map_err(report_buffer_write_error)?;
    } else {
        for (target_index, target_percent) in CONCENTRATION_TARGETS_PERCENT.iter().enumerate() {
            let sites_needed = summary
                .sites_reaching_percent
                .get(target_index)
                .copied()
                .unwrap_or(0);
            writeln!(
                report_writer,
                "  {:>3}% of all counts come from the hottest {} sites ({:.3}% of sites)",
                target_percent,
                sites_needed,
                percent_of_site_count(sites_needed, summary.site_count)
            )
            .map_err(report_buffer_write_error)?;
        }
        let last_target_index = CONCENTRATION_TARGET_COUNT.saturating_sub(1);
        let sites_for_last_target = summary
            .sites_reaching_percent
            .get(last_target_index)
            .copied()
            .unwrap_or(0);
        let last_target_percent = CONCENTRATION_TARGETS_PERCENT
            .get(last_target_index)
            .copied()
            .unwrap_or(100);
        let cold_tail_sites = summary.site_count.saturating_sub(sites_for_last_target);
        writeln!(
            report_writer,
            "  cold tail: {} sites ({:.2}% of sites) together carry <= {}% of counts",
            cold_tail_sites,
            percent_of_site_count(cold_tail_sites, summary.site_count),
            100u128.saturating_sub(last_target_percent)
        )
        .map_err(report_buffer_write_error)?;
    }

    writeln!(
        report_writer,
        "  order-of-magnitude histogram (non-empty buckets):"
    )
    .map_err(report_buffer_write_error)?;
    for (bucket_index, bucket_site_count) in summary.decade_histogram.iter().enumerate() {
        if *bucket_site_count == 0 {
            continue;
        }
        if bucket_index == 0 {
            writeln!(
                report_writer,
                "    count = 0            : {}",
                bucket_site_count
            )
            .map_err(report_buffer_write_error)?;
        } else {
            writeln!(
                report_writer,
                "    1e{:<2} <= count < 1e{:<2}: {}",
                bucket_index.saturating_sub(1),
                bucket_index,
                bucket_site_count
            )
            .map_err(report_buffer_write_error)?;
        }
    }

    writeln!(report_writer, "  top {} by count:", top_n_limit)
        .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  {:>5}  {:>20}  {:>9}  {:>6}  location  name",
        "rank", "count", "%kind", "log10"
    )
    .map_err(report_buffer_write_error)?;
    for (rank_index, site) in sorted_sites.iter().take(top_n_limit).enumerate() {
        let source_path_text = lookup_source_path(records, site.source_file_index)?;
        let line_value = site.line_number.sln_get()?;
        let share_percent = percent_of_total(site.execution_count, summary.total_count);
        let rank = rank_index.saturating_add(1);
        if site.execution_count == 0 {
            write!(
                report_writer,
                "  {:>5}  {:>20}  {:>8.4}%  {:>6}  ",
                rank, site.execution_count, share_percent, "-"
            )
            .map_err(report_buffer_write_error)?;
        } else {
            write!(
                report_writer,
                "  {:>5}  {:>20}  {:>8.4}%  {:>6.2}  ",
                rank,
                site.execution_count,
                share_percent,
                (site.execution_count as f64).log10()
            )
            .map_err(report_buffer_write_error)?;
        }
        write!(
            report_writer,
            "{}:{}  {}",
            source_path_text, line_value, site.display_name
        )
        .map_err(report_buffer_write_error)?;
        if site.merged_instance_count > 1 {
            write!(
                report_writer,
                "  [{} instances merged]",
                site.merged_instance_count
            )
            .map_err(report_buffer_write_error)?;
        }
        if let Some(enclosing_entry_count) = site.enclosing_function_entry_count {
            if enclosing_entry_count == 0 {
                if site.execution_count > 0 {
                    // A counted loop inside a never-entered fn means the
                    // nearest-preceding-FN attribution picked the wrong fn.
                    write!(
                        report_writer,
                        "  [enclosing fn count 0: attribution suspect]"
                    )
                    .map_err(report_buffer_write_error)?;
                }
            } else {
                write!(
                    report_writer,
                    "  [~{:.1} per call of enclosing fn]",
                    (site.execution_count as f64) / (enclosing_entry_count as f64)
                )
                .map_err(report_buffer_write_error)?;
            }
        }
        writeln!(report_writer).map_err(report_buffer_write_error)?;
    }
    Ok(())
}

/// Writes the `[DISTRIBUTION SHAPE]` section for functions and loops.
///
/// Marked experimental in the report: the figures are descriptive, for
/// comparing runs and programs, and are not verdicts. Definitions are in
/// `compute_distribution_shape`; a one-line legend is printed with the section.
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed)`, or a code from `compute_distribution_shape` /
///   `write_distribution_shape_for_kind`.
fn write_distribution_shape_section<W: Write>(
    report_writer: &mut W,
    inputs: &ReportInputs,
) -> Result<(), HeatmapError> {
    let last_target_percent = CONCENTRATION_TARGETS_PERCENT
        .get(CONCENTRATION_TARGET_COUNT.saturating_sub(1))
        .copied()
        .unwrap_or(100);
    writeln!(
        report_writer,
        "[DISTRIBUTION SHAPE]  (experimental: descriptive figures for comparing runs; not verdicts)"
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  gini            : 0 = every site has the same count; 1 = one site has every count"
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  empty-decade gap: orders of magnitude with no sites between occupied ones (a smooth spread has none)"
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  head drop       : largest count ratio between adjacent ranks among the sites carrying {}% of counts",
        last_target_percent
    )
    .map_err(report_buffer_write_error)?;
    write_distribution_shape_for_kind(
        report_writer,
        "FUNCTIONS",
        inputs.function_sites,
        inputs.function_summary,
        inputs.records,
    )?;
    write_distribution_shape_for_kind(
        report_writer,
        "LOOPS",
        inputs.loop_sites,
        inputs.loop_summary,
        inputs.records,
    )?;
    Ok(())
}

/// Writes the distribution-shape figures for one kind of site.
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed | AnaShapeInputNotSorted | AnaShapeSumOverflow |
///   AnaShapeDropIndexInvalid | AnaFileIndexInvalid | TypeLineNumberCorrupted)`.
fn write_distribution_shape_for_kind<W: Write>(
    report_writer: &mut W,
    kind_title: &str,
    sorted_sites: &[HeatSite],
    summary: &HeatKindSummary,
    records: &[FileCoverageRecord],
) -> Result<(), HeatmapError> {
    let shape = compute_distribution_shape(sorted_sites, summary)?;
    writeln!(report_writer, "  {}", kind_title).map_err(report_buffer_write_error)?;

    // All four figures exist exactly when the kind's total count is > 0.
    let (gini_all, gini_counted, top_narrow_share, top_wide_share) = match (
        shape.gini_all_sites,
        shape.gini_counted_sites,
        shape.top_narrow_share_percent,
        shape.top_wide_share_percent,
    ) {
        (Some(gini_all), Some(gini_counted), Some(top_narrow), Some(top_wide)) => {
            (gini_all, gini_counted, top_narrow, top_wide)
        }
        _ => {
            writeln!(report_writer, "    n/a (total count is 0)")
                .map_err(report_buffer_write_error)?;
            return Ok(());
        }
    };

    let top_narrow_label = format!("top-{} share", TOP_SHARE_NARROW_SITES);
    let top_wide_label = format!("top-{} share", TOP_SHARE_WIDE_SITES);
    let head_percent = CONCENTRATION_TARGETS_PERCENT
        .get(CONCENTRATION_TARGET_COUNT.saturating_sub(1))
        .copied()
        .unwrap_or(100);
    let head_drop_label = format!("largest drop within {}% head", head_percent);

    writeln!(
        report_writer,
        "    {:<32}: {:.4}",
        "gini, all sites", gini_all
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "    {:<32}: {:.4}",
        "gini, sites with count > 0", gini_counted
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "    {:<32}: {:.4}%",
        top_narrow_label, top_narrow_share
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "    {:<32}: {:.4}%",
        top_wide_label, top_wide_share
    )
    .map_err(report_buffer_write_error)?;

    match shape.largest_empty_decade_gap {
        Some(gap) => writeln!(
            report_writer,
            "    {:<32}: {} empty order(s) of magnitude: no sites with counts in [1e{}, 1e{})",
            "largest empty-decade gap",
            gap.empty_decade_count,
            gap.lower_bucket_index,
            gap.upper_bucket_index.saturating_sub(1)
        ),
        None => writeln!(
            report_writer,
            "    {:<32}: none",
            "largest empty-decade gap"
        ),
    }
    .map_err(report_buffer_write_error)?;

    match shape.largest_head_drop {
        Some(drop) => {
            let lower_position = match drop.higher_position.checked_add(1) {
                Some(position) => position,
                None => return Err(HeatmapError::AnaShapeDropIndexInvalid),
            };
            let (higher_site, lower_site) = match (
                sorted_sites.get(drop.higher_position),
                sorted_sites.get(lower_position),
            ) {
                (Some(higher_site), Some(lower_site)) => (higher_site, lower_site),
                _ => {
                    #[cfg(all(debug_assertions, not(test)))]
                    debug_assert!(
                        false,
                        "HIX-{}: drop position {} invalid",
                        HeatmapError::AnaShapeDropIndexInvalid.code(),
                        drop.higher_position
                    );
                    #[cfg(debug_assertions)]
                    eprintln!(
                        "HIX-{}: drop position {} invalid",
                        HeatmapError::AnaShapeDropIndexInvalid.code(),
                        drop.higher_position
                    );
                    return Err(HeatmapError::AnaShapeDropIndexInvalid);
                }
            };
            writeln!(
                report_writer,
                "    {:<32}: {:.4}x  rank {} -> {}  (count {} -> {})",
                head_drop_label,
                drop.drop_ratio,
                drop.higher_position.saturating_add(1),
                lower_position.saturating_add(1),
                higher_site.execution_count,
                lower_site.execution_count
            )
            .map_err(report_buffer_write_error)?;
            for (direction_label, site) in [("from", higher_site), ("to  ", lower_site)] {
                let source_path_text = lookup_source_path(records, site.source_file_index)?;
                let line_value = site.line_number.sln_get()?;
                writeln!(
                    report_writer,
                    "      {}  {}:{}  {}",
                    direction_label, source_path_text, line_value, site.display_name
                )
                .map_err(report_buffer_write_error)?;
            }
        }
        None => {
            writeln!(
                report_writer,
                "    {:<32}: none (fewer than 2 head sites, or equal counts)",
                head_drop_label
            )
            .map_err(report_buffer_write_error)?;
        }
    }
    Ok(())
}

/// Writes the CO-COUNT GROUPS section: hot sites (functions and loops
/// together) whose exact counts are identical.
///
/// # Project context
/// LLVM counts are exact. When two sites at >= `CO_COUNT_MIN_COUNT` share
/// exactly the same count, coincidence is unlikely and structural coupling is
/// likely. Typical causes: a 1:1 caller/callee pair (e.g. `calc_distance`
/// calling `distance`), or a function called once per iteration of a loop.
/// Such groups are candidates for fusion or inlining review: a hint for a
/// human, not a verdict. Equal counts on code that ran across threads are
/// also mild evidence that counter-increment loss was negligible there.
///
/// # Method
/// 1. Collect all function and loop sites with count >= `CO_COUNT_MIN_COUNT`.
/// 2. Sort by count descending (tie-break: kind, file, line, so the output
///    is deterministic).
/// 3. Pass 1: find runs of identical counts of length >= 2.
/// 4. Pass 2: write the number of groups found, then up to `top_n_limit` groups.
///
/// # Arguments
/// - `report_writer`: in-memory report buffer.
/// - `inputs`: all report data (sites, records for path lookup, Top-N limit).
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed | AnaCoCountRunInvalid | AnaFileIndexInvalid |
///   TypeLineNumberCorrupted)`, each from its own failure site.
fn write_co_count_groups<W: Write>(
    report_writer: &mut W,
    inputs: &ReportInputs,
) -> Result<(), HeatmapError> {
    let mut co_count_members: Vec<(&'static str, &HeatSite)> = Vec::new();
    for site in inputs.function_sites.iter() {
        if site.execution_count >= CO_COUNT_MIN_COUNT {
            co_count_members.push(("function", site));
        }
    }
    for site in inputs.loop_sites.iter() {
        if site.execution_count >= CO_COUNT_MIN_COUNT {
            co_count_members.push(("loop", site));
        }
    }
    co_count_members.sort_by(|(left_kind, left_site), (right_kind, right_site)| {
        right_site
            .execution_count
            .cmp(&left_site.execution_count)
            .then_with(|| left_kind.cmp(right_kind))
            .then_with(|| {
                left_site
                    .source_file_index
                    .cmp(&right_site.source_file_index)
            })
            .then_with(|| left_site.line_number.cmp(&right_site.line_number))
    });

    // Pass 1: find runs of identical counts (length >= 2). Bounded by list length.
    let mut run_ranges: Vec<(usize, usize)> = Vec::new();
    let mut run_start_index: usize = 0;
    for current_index in 1..=co_count_members.len() {
        let run_continues = match (
            co_count_members.get(current_index),
            co_count_members.get(run_start_index),
        ) {
            (Some((_, current_site)), Some((_, start_site))) => {
                current_site.execution_count == start_site.execution_count
            }
            _ => false,
        };
        if run_continues {
            continue;
        }
        if current_index.saturating_sub(run_start_index) >= 2 {
            run_ranges.push((run_start_index, current_index));
        }
        run_start_index = current_index;
    }

    // Pass 2: write.
    writeln!(
        report_writer,
        "[CO-COUNT GROUPS]  (identical exact counts >= {}; likely structural coupling)",
        CO_COUNT_MIN_COUNT
    )
    .map_err(report_buffer_write_error)?;
    writeln!(
        report_writer,
        "  groups found: {}   (showing up to {})",
        run_ranges.len(),
        inputs.top_n_limit
    )
    .map_err(report_buffer_write_error)?;

    for (group_index, (run_start, run_end)) in
        run_ranges.iter().take(inputs.top_n_limit).enumerate()
    {
        let run_members = match co_count_members.get(*run_start..*run_end) {
            Some(members) => members,
            None => {
                #[cfg(all(debug_assertions, not(test)))]
                debug_assert!(
                    false,
                    "HIX-{}: co-count run {}..{} invalid",
                    HeatmapError::AnaCoCountRunInvalid.code(),
                    run_start,
                    run_end
                );
                #[cfg(debug_assertions)]
                eprintln!(
                    "HIX-{}: co-count run {}..{} invalid",
                    HeatmapError::AnaCoCountRunInvalid.code(),
                    run_start,
                    run_end
                );
                return Err(HeatmapError::AnaCoCountRunInvalid);
            }
        };
        let shared_count = run_members
            .first()
            .map(|(_, site)| site.execution_count)
            .unwrap_or(0);
        writeln!(
            report_writer,
            "  group {}: count {}, {} sites",
            group_index.saturating_add(1),
            shared_count,
            run_members.len()
        )
        .map_err(report_buffer_write_error)?;
        for (kind_label, site) in run_members.iter() {
            let source_path_text = lookup_source_path(inputs.records, site.source_file_index)?;
            let line_value = site.line_number.sln_get()?;
            writeln!(
                report_writer,
                "    {:<8}  {}:{}  {}",
                kind_label, source_path_text, line_value, site.display_name
            )
            .map_err(report_buffer_write_error)?;
        }
    }
    Ok(())
}

/// Writes every site (functions first, then loops; each hottest-first) as TSV.
///
/// # Project context
/// The TSV is the machine-readable data product: complete (not Top-N), with
/// stable identity `source_path` + `line`, intended to join
/// time-heat (perf) onto count-heat.
///
/// # Column contract (append-only)
/// `kind, rank, count, percent_of_kind, log10_count, source_path, line, name,
/// merged_instances, per_enclosing_call` and, only when `--work-units` was
/// given, `count_per_work_unit`. New columns are only ever
/// appended at the end, so tools that read existing columns by position keep
/// working.
/// Empty fields: `log10_count` when count is 0; `per_enclosing_call` for
/// function rows and for loops without a nonzero enclosing count.
/// Fields are not escaped (documented limitation).
///
/// # Returns
/// - `Ok(())`, or an error code from `write_tsv_rows` / `RptBufferWriteFailed` /
///   `TypeWorkUnitsCorrupted`.
fn write_sites_tsv<W: Write>(
    tsv_writer: &mut W,
    inputs: &ReportInputs,
) -> Result<(), HeatmapError> {
    let work_unit_count = match &inputs.run_metadata.work_units {
        Some(work_units) => Some(work_units.count.wuc_get()?),
        None => None,
    };
    write!(
        tsv_writer,
        "kind\trank\tcount\tpercent_of_kind\tlog10_count\tsource_path\tline\tname\tmerged_instances\tper_enclosing_call"
    )
    .map_err(report_buffer_write_error)?;
    if work_unit_count.is_some() {
        write!(tsv_writer, "\tcount_per_work_unit").map_err(report_buffer_write_error)?;
    }
    writeln!(tsv_writer).map_err(report_buffer_write_error)?;
    write_tsv_rows(
        tsv_writer,
        "function",
        inputs.function_sites,
        inputs.function_summary,
        inputs.records,
        work_unit_count,
    )?;
    write_tsv_rows(
        tsv_writer,
        "loop",
        inputs.loop_sites,
        inputs.loop_summary,
        inputs.records,
        work_unit_count,
    )?;
    Ok(())
}

/// Writes the TSV rows for one kind of site (see `write_sites_tsv` for the
/// column contract).
///
/// # Arguments
/// - `tsv_writer`: in-memory TSV buffer.
/// - `kind_label`: `"function"` or `"loop"` (first column).
/// - `sorted_sites`: one kind's sites, hottest-first (rank = position + 1).
/// - `summary`: that kind's summary (its total is the percent denominator).
/// - `records`: used to resolve each site's file index to its source path.
/// - `work_unit_count`: `Some(n)` (n >= 1) appends `count_per_work_unit`.
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed | AnaFileIndexInvalid | TypeLineNumberCorrupted)`.
/// Writes the TSV rows for one kind of site (see `write_sites_tsv` for the
/// column contract).
///
/// # Arguments
/// - `tsv_writer`: in-memory TSV buffer.
/// - `kind_label`: `"function"` or `"loop"` (first column).
/// - `sorted_sites`: one kind's sites, hottest-first (rank = position + 1).
/// - `summary`: that kind's summary (its total is the percent denominator).
/// - `records`: used to resolve each site's file index to its source path.
/// - `work_unit_count`: `Some(n)` (n >= 1) appends column 11,
///   `count_per_work_unit`, to every row; `None` writes 10 columns.
///
/// # Returns
/// - `Ok(())`.
/// - `Err(RptBufferWriteFailed | AnaFileIndexInvalid | TypeLineNumberCorrupted)`.
fn write_tsv_rows<W: Write>(
    tsv_writer: &mut W,
    kind_label: &str,
    sorted_sites: &[HeatSite],
    summary: &HeatKindSummary,
    records: &[FileCoverageRecord],
    work_unit_count: Option<u64>,
) -> Result<(), HeatmapError> {
    for (rank_index, site) in sorted_sites.iter().enumerate() {
        let source_path_text = lookup_source_path(records, site.source_file_index)?;
        let line_value = site.line_number.sln_get()?;
        let share_percent = percent_of_total(site.execution_count, summary.total_count);

        // Columns 1-4: kind, rank, count, percent_of_kind (each followed by a tab).
        write!(
            tsv_writer,
            "{}\t{}\t{}\t{:.6}\t",
            kind_label,
            rank_index.saturating_add(1),
            site.execution_count,
            share_percent
        )
        .map_err(report_buffer_write_error)?;

        // Column 5: log10_count (empty when count is 0).
        if site.execution_count > 0 {
            write!(tsv_writer, "{:.4}", (site.execution_count as f64).log10())
                .map_err(report_buffer_write_error)?;
        }

        // Columns 6-9: source_path, line, name, merged_instances
        // (the leading tab ends column 5; the trailing tab starts column 10).
        write!(
            tsv_writer,
            "\t{}\t{}\t{}\t{}\t",
            source_path_text, line_value, site.display_name, site.merged_instance_count
        )
        .map_err(report_buffer_write_error)?;

        // Column 10: per_enclosing_call (empty for functions, and for loops
        // without a nonzero enclosing count).
        if let Some(enclosing_entry_count) = site.enclosing_function_entry_count {
            if enclosing_entry_count > 0 {
                write!(
                    tsv_writer,
                    "{:.4}",
                    (site.execution_count as f64) / (enclosing_entry_count as f64)
                )
                .map_err(report_buffer_write_error)?;
            }
        }

        // Column 11 (only when work units were given): count_per_work_unit.
        // Written for every row, outside the column-10 block above.
        if let Some(unit_count) = work_unit_count {
            write!(
                tsv_writer,
                "\t{:.6}",
                (site.execution_count as f64) / (unit_count as f64)
            )
            .map_err(report_buffer_write_error)?;
        }

        // End of row.
        writeln!(tsv_writer).map_err(report_buffer_write_error)?;
    }
    Ok(())
}

// ============================================================================
// Tests (test mode only)
// ============================================================================

/// Unit tests (compiled only under `cargo test`).
///
/// All tests use in-memory input (`std::io::Cursor`) and synthetic sites, so
/// they touch no files except `std::env::temp_dir()` path *values* (never
/// created or opened). `unwrap`/`assert!` are allowed here (test mode).
///
/// Test names: `<area>_<function>_<condition>[_with_code_<nnn>]`.
/// Areas: `cli`, `type`, `lcov`, `src` (loop scan), `ana` (analysis),
/// `rpt` (report output), `err` (error-code policy), `guard`
/// (single-source-of-truth checks on the source text itself).
///
/// Most tests use in-memory input (`std::io::Cursor`) and synthetic sites.
/// Output-safety tests (`rpt_*` for codes 510–515) create and remove
/// uniquely named entries under `std::env::temp_dir()`; if such a test
/// fails mid-way, its temp entry may remain (harmless, unique name).
/// `unwrap`/`assert!` are allowed here (test mode).
#[cfg(test)]
mod hix_heatmap_indices_for_compute_tests {
    use super::*;
    use std::io::Cursor;

    /// One file, two monomorphized instances of `tick` at line 1 (500 + 250
    /// calls), a cold `idle` at line 9, and a hot loop header at line 3
    /// (75_750 executions = 101 per call of `tick`).
    const SAMPLE_LCOV: &str = "TN:\n\
SF:/abs/src/world.rs\n\
FN:1,_ZN5world4tick17h0E\n\
FN:1,_ZN5world4tick17h1E\n\
FN:9,_ZN5world4idle17h2E\n\
FNDA:500,_ZN5world4tick17h0E\n\
FNDA:250,_ZN5world4tick17h1E\n\
FNDA:0,_ZN5world4idle17h2E\n\
FNF:3\n\
FNH:2\n\
DA:1,750\n\
DA:3,75750\n\
DA:9,0\n\
LF:3\n\
LH:2\n\
end_of_record\n";

    /// Source text matching `SAMPLE_LCOV`: one real loop at line 3, plus a
    /// loop keyword inside a line comment (line 2) and inside a block comment
    /// (lines 5-6) that must NOT be detected.
    const SAMPLE_SOURCE: &str = "fn tick() {\n\
    // for x in not_a_loop\n\
    for entity in entities {\n\
    }\n\
    /* while\n\
       loop */\n\
}\n\
\n\
fn idle() {}\n";

    /// Parses `SAMPLE_LCOV` into coverage records (panics on failure: test mode).
    fn parse_sample() -> Vec<FileCoverageRecord> {
        let mut cursor = Cursor::new(SAMPLE_LCOV.as_bytes());
        parse_lcov_reader(&mut cursor).unwrap()
    }

    /// Builds a synthetic site in file index 0 with the given count and line.
    /// `enclosing_function_entry_count` is `None` (function-site style).
    fn make_site(execution_count: u64, line: u32) -> HeatSite {
        HeatSite {
            source_file_index: 0,
            line_number: SourceLineNumber::sln_new(line).unwrap(),
            display_name: String::from("test_site"),
            execution_count,
            merged_instance_count: 1,
            enclosing_function_entry_count: None,
        }
    }

    /// Renders the text report for synthetic site lists (no file notes, Top-N 10).
    /// Sites must already be hottest-first (callers pass sorted vectors).
    fn render_text_report(
        records: &[FileCoverageRecord],
        function_sites: &[HeatSite],
        loop_sites: &[HeatSite],
    ) -> String {
        render_text_report_with_notes(
            records,
            function_sites,
            loop_sites,
            &LoopScanFileNotes::default(),
            10,
        )
    }
    /// Renders the text report and the TSV for synthetic inputs.
    fn render_reports(
        records: &[FileCoverageRecord],
        function_sites: &[HeatSite],
        loop_sites: &[HeatSite],
        file_notes: &LoopScanFileNotes,
        run_metadata: &RunMetadata,
        top_n_limit: usize,
    ) -> (String, String) {
        let function_summary = summarize_sorted_sites(function_sites).unwrap();
        let loop_summary = summarize_sorted_sites(loop_sites).unwrap();
        let statistics = LoopScanStatistics::default();
        let report_path = std::env::temp_dir().join("r.txt");
        let tsv_path = std::env::temp_dir().join("s.tsv");
        let lcov_path = std::env::temp_dir().join("in.lcov");
        let inputs = ReportInputs {
            lcov_input_path: &lcov_path,
            report_file_path: &report_path,
            sites_tsv_file_path: &tsv_path,
            records,
            function_sites,
            function_summary: &function_summary,
            loop_sites,
            loop_summary: &loop_summary,
            loop_scan_statistics: &statistics,
            loop_scan_file_notes: file_notes,
            run_metadata,
            top_n_limit,
            duplicate_function_name_count: 0,
            duplicate_source_path_count: 0,
        };
        let mut report_bytes: Vec<u8> = Vec::new();
        write_text_report(&mut report_bytes, &inputs).unwrap();
        let mut tsv_bytes: Vec<u8> = Vec::new();
        write_sites_tsv(&mut tsv_bytes, &inputs).unwrap();
        (
            String::from_utf8(report_bytes).unwrap(),
            String::from_utf8(tsv_bytes).unwrap(),
        )
    }

    /// Renders the text report with explicit file notes and Top-N limit.
    fn render_text_report_with_notes(
        records: &[FileCoverageRecord],
        function_sites: &[HeatSite],
        loop_sites: &[HeatSite],
        file_notes: &LoopScanFileNotes,
        top_n_limit: usize,
    ) -> String {
        render_reports(
            records,
            function_sites,
            loop_sites,
            file_notes,
            &RunMetadata::default(),
            top_n_limit,
        )
        .0
    }

    /// LCOV parsing: one SF record with all FN/DA entries and the file max count.
    #[test]
    fn lcov_parse_lcov_reader_reads_one_record() {
        let records = parse_sample();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source_path_text, "/abs/src/world.rs");
        assert_eq!(records[0].function_definitions.len(), 3);
        assert_eq!(records[0].max_line_execution_count, 75_750);
    }

    /// Function sites: two instances at line 1 merge into one site (750 calls),
    /// and mangled names are unique, so the duplicate-name counter stays 0.
    #[test]
    fn ana_build_function_sites_merges_monomorphized_instances() {
        let records = parse_sample();
        let (mut sites, duplicate_function_name_count) = build_function_sites(&records).unwrap();
        sort_sites_hottest_first(&mut sites);
        assert_eq!(duplicate_function_name_count, 0);
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].execution_count, 750);
        assert_eq!(sites[0].merged_instance_count, 2);
        assert_eq!(sites[0].enclosing_function_entry_count, None);
        assert_eq!(sites[1].execution_count, 0);
    }

    /// Loop scan: finds the real header at line 3 and ignores keywords in comments.
    #[test]
    fn src_scan_source_reader_finds_header_and_skips_comments() {
        let records = parse_sample();
        let mut source_cursor = Cursor::new(SAMPLE_SOURCE.as_bytes());
        let outcome = scan_source_reader(&mut source_cursor, 0, &records[0]).unwrap();
        assert_eq!(outcome.loop_headers_found, 1);
        assert_eq!(outcome.loop_sites.len(), 1);
        assert_eq!(outcome.loop_sites[0].execution_count, 75_750);
        assert_eq!(outcome.loop_sites[0].line_number.sln_get().unwrap(), 3);
        assert!(outcome.loop_sites[0].display_name.contains("tick"));
    }

    /// Loop scan: the loop records its enclosing function's summed entry
    /// count (500 + 250), and the report shows the per-call ratio (101.0).
    #[test]
    fn src_scan_source_reader_records_enclosing_function_count() {
        let records = parse_sample();
        let mut source_cursor = Cursor::new(SAMPLE_SOURCE.as_bytes());
        let outcome = scan_source_reader(&mut source_cursor, 0, &records[0]).unwrap();
        assert_eq!(
            outcome.loop_sites[0].enclosing_function_entry_count,
            Some(750)
        );
        let report_text = render_text_report(&records, &[], &outcome.loop_sites);
        assert!(report_text.contains("~101.0 per call of enclosing fn"));
    }

    /// Keyword detection: accepted loop forms and rejected look-alikes.
    #[test]
    fn src_detect_loop_keyword_accepts_and_rejects_cases() {
        assert_eq!(
            detect_loop_keyword(b"for x in items {"),
            Some(LoopKeyword::For)
        );
        assert_eq!(
            detect_loop_keyword(b"while let Some(x) = q.pop() {"),
            Some(LoopKeyword::While)
        );
        assert_eq!(detect_loop_keyword(b"loop {"), Some(LoopKeyword::Loop));
        assert_eq!(detect_loop_keyword(b"loop{"), Some(LoopKeyword::Loop));
        assert_eq!(
            detect_loop_keyword(b"'outer: loop {"),
            Some(LoopKeyword::Loop)
        );
        assert_eq!(
            detect_loop_keyword(b"'rows: for r in 0..n {"),
            Some(LoopKeyword::For)
        );
        assert_eq!(detect_loop_keyword(b"for<'a> Fn(&'a u8)"), None);
        assert_eq!(detect_loop_keyword(b"forward(x);"), None);
        assert_eq!(detect_loop_keyword(b"loopy();"), None);
        assert_eq!(detect_loop_keyword(b"'a'"), None);
        assert_eq!(detect_loop_keyword(b"let x = 1;"), None);
    }

    #[test]
    fn lcov_parse_unterminated_record_with_code_214() {
        let mut cursor = Cursor::new("SF:/abs/a.rs\nDA:1,1\n".as_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovUnterminatedRecord);
        assert_eq!(error.code(), 214);
    }

    #[test]
    fn lcov_parse_entry_outside_file_with_code_209() {
        let mut cursor = Cursor::new("DA:1,1\n".as_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovRecordOutsideFile);
        assert_eq!(error.code(), 209);
    }

    #[test]
    fn lcov_parse_empty_input_with_code_215() {
        let mut cursor = Cursor::new("".as_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovNoData);
        assert_eq!(error.code(), 215);
    }

    #[test]
    fn lcov_parse_bad_count_with_code_211() {
        let mut cursor = Cursor::new("SF:/abs/a.rs\nDA:1,abc\nend_of_record\n".as_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovBadCount);
        assert_eq!(error.code(), 211);
    }

    #[test]
    fn lcov_parse_zero_line_number_with_code_210() {
        let mut cursor = Cursor::new("SF:/abs/a.rs\nDA:0,1\nend_of_record\n".as_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovBadLineNumber);
        assert_eq!(error.code(), 210);
    }

    #[test]
    fn lcov_parse_line_too_long_with_code_206() {
        let mut cursor = Cursor::new("x".repeat(MAX_LINE_BYTES + 10).into_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovLineTooLong);
        assert_eq!(error.code(), 206);
    }

    /// Duplicate-name integrity check: two `FN` entries with one name in one
    /// file are counted (the condition that arises if LCOV is demangled first).
    #[test]
    fn ana_build_function_sites_counts_duplicate_names() {
        let lcov_text = "SF:/abs/a.rs\nFN:1,same\nFN:5,same\nFNDA:3,same\nDA:1,3\nend_of_record\n";
        let records = parse_lcov_reader(&mut Cursor::new(lcov_text.as_bytes())).unwrap();
        let (sites, duplicate_function_name_count) = build_function_sites(&records).unwrap();
        assert_eq!(sites.len(), 2);
        assert_eq!(duplicate_function_name_count, 1);
    }

    /// Summary on sorted input: totals, concentration, and decade histogram.
    #[test]
    fn ana_summarize_sorted_sites_concentration_and_histogram() {
        let mut sites = vec![
            make_site(9, 2),
            make_site(90, 1),
            make_site(0, 4),
            make_site(1, 3),
        ];
        sort_sites_hottest_first(&mut sites);
        let summary = summarize_sorted_sites(&sites).unwrap();
        assert_eq!(summary.total_count, 100);
        assert_eq!(summary.zero_count_sites, 1);
        assert_eq!(summary.sites_reaching_percent, [1, 1, 2]);
        assert_eq!(summary.decade_histogram[0], 1); // count 0
        assert_eq!(summary.decade_histogram[1], 2); // 1 and 9
        assert_eq!(summary.decade_histogram[2], 1); // 90
    }

    /// Regression guard: Unsorted input must
    /// produce the same concentration as sorted input.
    /// (Unsorted summarize of [1, 9, 0, 90] would wrongly report 4 sites for 50%.)
    #[test]
    fn ana_sort_and_summarize_sites_handles_unsorted_input() {
        let mut sites = vec![
            make_site(1, 3),
            make_site(9, 2),
            make_site(0, 4),
            make_site(90, 1),
        ];
        let summary = sort_and_summarize_sites(&mut sites).unwrap();
        assert_eq!(sites[0].execution_count, 90);
        assert_eq!(summary.sites_reaching_percent, [1, 1, 2]);
    }

    /// Summary when every count is 0: not an error; concentration is "n/a".
    #[test]
    fn ana_summarize_sorted_sites_all_zero_counts_not_an_error() {
        let sites = vec![make_site(0, 1), make_site(0, 2)];
        let summary = summarize_sorted_sites(&sites).unwrap();
        assert_eq!(summary.total_count, 0);
        assert_eq!(summary.sites_reaching_percent, [0, 0, 0]);
    }

    #[test]
    fn type_top_n_count_new_out_of_range_with_code_150() {
        let error = TopNCount::tnc_new(0).unwrap_err();
        assert_eq!(error, HeatmapError::TypeTopNOutOfRange);
        assert_eq!(error.code(), 150);
        assert_eq!(
            TopNCount::tnc_new(MAX_TOP_N + 1).unwrap_err(),
            HeatmapError::TypeTopNOutOfRange
        );
        assert_eq!(TopNCount::tnc_new(5).unwrap().tnc_get().unwrap(), 5);
    }

    #[test]
    fn type_source_line_number_new_zero_with_code_152() {
        let error = SourceLineNumber::sln_new(0).unwrap_err();
        assert_eq!(error, HeatmapError::TypeLineNumberZero);
        assert_eq!(error.code(), 152);
    }

    #[test]
    fn type_absolute_path_new_relative_with_code_154() {
        let error = AbsolutePath::ap_new(PathBuf::from("relative/x.lcov")).unwrap_err();
        assert_eq!(error, HeatmapError::TypePathNotAbsolute);
        assert_eq!(error.code(), 154);
    }

    /// Command line: valid flags in any order produce a validated configuration.
    #[test]
    fn cli_parse_cli_arguments_accepts_valid_arguments() {
        let lcov_path = std::env::temp_dir().join("chm_test_input.lcov");
        let output_path = std::env::temp_dir().join("chm_test_out");
        let arguments = vec![
            OsString::from("hix"), // argument 0 (program name): skipped by the parser
            OsString::from("--lcov"),
            lcov_path.clone().into_os_string(),
            OsString::from("--out-dir"),
            output_path.into_os_string(),
            OsString::from("--top-n"),
            OsString::from("7"),
        ];
        let configuration = parse_cli_arguments(arguments.into_iter()).unwrap();
        assert_eq!(configuration.top_n.tnc_get().unwrap(), 7);
        assert_eq!(
            configuration.lcov_input_path.ap_get().unwrap(),
            lcov_path.as_path()
        );
    }

    #[test]
    fn cli_parse_cli_arguments_missing_value_with_code_103() {
        let error = cli_error(&["hix", "--lcov"]).unwrap();
        assert_eq!(error, HeatmapError::CliMissingFlagValue);
        assert_eq!(error.code(), 103);
    }

    #[test]
    fn cli_parse_cli_arguments_unknown_flag_with_code_102() {
        let error = cli_error(&["hix", "--nope", "x"]).unwrap();
        assert_eq!(error, HeatmapError::CliUnknownFlag);
        assert_eq!(error.code(), 102);
    }

    #[test]
    fn cli_parse_cli_arguments_relative_path_with_code_154() {
        let error =
            cli_error(&["hix", "--lcov", "relative.lcov", "--out-dir", "/abs/out"]).unwrap();
        assert_eq!(error, HeatmapError::TypePathNotAbsolute);
        assert_eq!(error.code(), 154);
    }

    /// Retry policy is defined per code: only transient open errors retry.
    #[test]
    fn err_is_retryable_only_transient_open_codes() {
        assert!(HeatmapError::LcovOpenTransient.is_retryable());
        assert!(!HeatmapError::LcovOpenNotFound.is_retryable());
        assert!(!HeatmapError::AnaCountOverflow.is_retryable());
    }

    /// End-to-end rendering: text report sections present; TSV has one header
    /// row plus one row per site (2 functions + 1 loop).
    #[test]
    fn rpt_write_text_report_and_tsv_render() {
        let records = parse_sample();
        let (mut function_sites, _duplicate_function_name_count) =
            build_function_sites(&records).unwrap();
        let function_summary = sort_and_summarize_sites(&mut function_sites).unwrap();
        let mut loop_sites = vec![make_site(75_750, 3)];
        let loop_summary = sort_and_summarize_sites(&mut loop_sites).unwrap();
        let statistics = LoopScanStatistics::default();
        let report_path = std::env::temp_dir().join("r.txt");
        let tsv_path = std::env::temp_dir().join("s.tsv");
        let lcov_path = std::env::temp_dir().join("in.lcov");
        let file_notes = LoopScanFileNotes::default();
        let run_metadata = RunMetadata::default();
        let inputs = ReportInputs {
            lcov_input_path: &lcov_path,
            report_file_path: &report_path,
            sites_tsv_file_path: &tsv_path,
            records: &records,
            function_sites: &function_sites,
            function_summary: &function_summary,
            loop_sites: &loop_sites,
            loop_summary: &loop_summary,
            loop_scan_statistics: &statistics,
            loop_scan_file_notes: &file_notes,
            top_n_limit: 10,
            duplicate_function_name_count: 0,
            duplicate_source_path_count: 0,
            run_metadata: &run_metadata,
        };

        let mut report_bytes: Vec<u8> = Vec::new();
        write_text_report(&mut report_bytes, &inputs).unwrap();
        let report_text = String::from_utf8(report_bytes).unwrap();
        assert!(report_text.contains("[FUNCTIONS]"));
        assert!(report_text.contains("[LOOPS]"));
        assert!(report_text.contains("[CO-COUNT GROUPS]"));
        assert!(report_text.contains("2 instances merged"));
        assert!(report_text.contains("[loop-scan file notes]"));

        let mut tsv_bytes: Vec<u8> = Vec::new();
        write_sites_tsv(&mut tsv_bytes, &inputs).unwrap();
        let tsv_text = String::from_utf8(tsv_bytes).unwrap();
        assert_eq!(tsv_text.lines().count(), 1 + 2 + 1);
        assert!(
            tsv_text
                .lines()
                .next()
                .unwrap()
                .ends_with("\tper_enclosing_call")
        );
    }

    /// Co-count groups: two hot groups are found (2 functions; 1 function +
    /// 1 loop); identical counts below CO_COUNT_MIN_COUNT are ignored.
    #[test]
    fn rpt_write_co_count_groups_detects_identical_hot_counts() {
        let records = parse_sample();
        let function_sites = vec![
            make_site(292_014_254, 1),
            make_site(292_014_254, 2),
            make_site(5_000_000, 3),
            make_site(7, 4),
            make_site(7, 5), // identical but below CO_COUNT_MIN_COUNT: ignored
        ];
        let loop_sites = vec![make_site(5_000_000, 9)];
        let report_text = render_text_report(&records, &function_sites, &loop_sites);
        assert!(report_text.contains("[CO-COUNT GROUPS]"));
        assert!(report_text.contains("groups found: 2"));
        assert!(report_text.contains("count 292014254, 2 sites"));
        assert!(report_text.contains("count 5000000, 2 sites"));
    }

    /// Parses LCOV text into records (panics on failure: test mode).
    fn parse_lcov_text(lcov_text: &str) -> Vec<FileCoverageRecord> {
        parse_lcov_reader(&mut Cursor::new(lcov_text.as_bytes())).unwrap()
    }

    /// A 70 KiB line no longer skips the file;
    /// the loop on the following line is found with the correct line number,
    /// count, and enclosing-function count.
    #[test]
    fn src_scan_source_reader_overlong_line_keeps_file_and_finds_next_loop() {
        let records = parse_lcov_text(
            "SF:/abs/src/gen.rs\nFN:1,_ZN3gen4fill17h0E\nFNDA:5,_ZN3gen4fill17h0E\nDA:1,5\nDA:3,500\nend_of_record\n",
        );
        let long_array_body = "1,".repeat(35 * 1024); // 71_680 bytes
        assert!(long_array_body.len() > MAX_LINE_BYTES);
        let source_text = format!(
            "fn fill() {{\n    const T: [u8; 1] = [{}];\n    for x in items {{\n    }}\n}}\n",
            long_array_body
        );
        let outcome =
            scan_source_reader(&mut Cursor::new(source_text.as_bytes()), 0, &records[0]).unwrap();
        assert_eq!(outcome.overlong_lines_found, 1);
        assert_eq!(outcome.loop_headers_found, 1);
        assert_eq!(outcome.loop_sites.len(), 1);
        assert_eq!(outcome.loop_sites[0].line_number.sln_get().unwrap(), 3);
        assert_eq!(outcome.loop_sites[0].execution_count, 500);
        assert_eq!(
            outcome.loop_sites[0].enclosing_function_entry_count,
            Some(5)
        );
    }

    /// Edge case: a line exactly one byte too long, whose extra byte is its
    /// newline, has already ended. Nothing may be discarded, otherwise the
    /// next line (the loop) would be destroyed and line numbers would shift.
    #[test]
    fn src_read_source_line_one_byte_over_limit_keeps_next_line() {
        let records = parse_lcov_text(
            "SF:/abs/src/edge.rs\nFN:2,_ZN4edge1f17h0E\nFNDA:1,_ZN4edge1f17h0E\nDA:2,7\nend_of_record\n",
        );
        let mut source_text = "x".repeat(MAX_LINE_BYTES);
        source_text.push('\n');
        source_text.push_str("for y in z {\n}\n");
        let outcome =
            scan_source_reader(&mut Cursor::new(source_text.as_bytes()), 0, &records[0]).unwrap();
        assert_eq!(outcome.overlong_lines_found, 1);
        assert_eq!(outcome.loop_sites.len(), 1);
        assert_eq!(outcome.loop_sites[0].line_number.sln_get().unwrap(), 2);
        assert_eq!(outcome.loop_sites[0].execution_count, 7);
    }

    /// A block comment whose `*/` is split exactly between the kept start
    /// (ending in `*`) and the discarded part (starting with `/`) is still
    /// seen as closed, so the loop after it is found.
    #[test]
    fn src_scan_source_reader_sees_comment_end_split_across_discard() {
        let records = parse_lcov_text(
            "SF:/abs/src/cmt.rs\nFN:1,_ZN3cmt1f17h0E\nFNDA:2,_ZN3cmt1f17h0E\nDA:4,9\nend_of_record\n",
        );
        // Line 3: MAX_LINE_BYTES 'x', then "*/". The kept start is
        // MAX_LINE_BYTES + 1 bytes, so it ends with '*'; the discarded part is "/\n".
        let mut source_text = String::from("fn f() {\n/* comment start\n");
        source_text.push_str(&"x".repeat(MAX_LINE_BYTES));
        source_text.push_str("*/\n");
        source_text.push_str("for a in b {\n}\n}\n");
        let outcome =
            scan_source_reader(&mut Cursor::new(source_text.as_bytes()), 0, &records[0]).unwrap();
        assert_eq!(outcome.overlong_lines_found, 1);
        assert_eq!(outcome.loop_sites.len(), 1);
        assert_eq!(outcome.loop_sites[0].line_number.sln_get().unwrap(), 4);
    }

    /// A loop header at the start of an over-long line is detected from the
    /// kept start of the line.
    #[test]
    fn src_scan_source_reader_detects_loop_at_start_of_overlong_line() {
        let records = parse_lcov_text(
            "SF:/abs/src/big.rs\nFN:1,_ZN3big1g17h0E\nFNDA:3,_ZN3big1g17h0E\nDA:2,42\nend_of_record\n",
        );
        let source_text = format!(
            "fn g() {{\n    for v in [{}] {{\n    }}\n}}\n",
            "0,".repeat(35 * 1024)
        );
        let outcome =
            scan_source_reader(&mut Cursor::new(source_text.as_bytes()), 0, &records[0]).unwrap();
        assert_eq!(outcome.overlong_lines_found, 1);
        assert_eq!(outcome.loop_sites.len(), 1);
        assert_eq!(outcome.loop_sites[0].line_number.sln_get().unwrap(), 2);
        assert_eq!(outcome.loop_sites[0].execution_count, 42);
    }

    #[test]
    fn src_discard_rest_of_source_line_exceeds_cap_with_code_308() {
        let mut no_newline = Cursor::new(b"xxxxxxxxxx".to_vec());
        let error = discard_rest_of_source_line(&mut no_newline, false, 4).unwrap_err();
        assert_eq!(error, HeatmapError::SrcLineExceedsSkipCap);
        assert_eq!(error.code(), 308);
    }

    /// Discarding stops right after the newline (the next line stays
    /// readable) and detects `*/`, including a `*` carried from the kept part.
    #[test]
    fn src_discard_rest_of_source_line_stops_at_newline_and_sees_comment_end() {
        let mut with_newline = Cursor::new(b"abc*/def\nNEXT\n".to_vec());
        assert!(discard_rest_of_source_line(&mut with_newline, false, 100).unwrap());
        let mut next_line: Vec<u8> = Vec::new();
        with_newline.read_until(b'\n', &mut next_line).unwrap();
        assert_eq!(next_line, b"NEXT\n".to_vec());

        let mut carried_star = Cursor::new(b"/rest\n".to_vec());
        assert!(discard_rest_of_source_line(&mut carried_star, true, 100).unwrap());

        let mut no_comment_end = Cursor::new(b"*x/\n".to_vec());
        assert!(!discard_rest_of_source_line(&mut no_comment_end, false, 100).unwrap());
    }

    /// Single source of truth for error-code numbers.
    ///
    /// The enum discriminant is the only place a code number may be written.
    /// Every message must obtain it with `HeatmapError::Variant.code()`.
    /// This test reads this module and `main.rs` (compiled in as text) and
    /// fails if the marker "HIX-" is directly followed by a digit anywhere,
    /// naming the file and line. Renumbering codes therefore cannot leave a
    /// stale number behind in any message.
    #[test]
    fn guard_source_contains_no_hard_coded_error_code_numbers() {
        let source_files: [(&str, &str); 2] = [
            (
                "hix_heatmap_indices_for_compute.rs",
                include_str!("hix_heatmap_indices_for_compute.rs"),
            ),
            ("main.rs", include_str!("main.rs")),
        ];
        let marker = "HIX-";
        for (file_name, source_text) in source_files.iter() {
            for (line_index, line_text) in source_text.lines().enumerate() {
                for (found_index, _) in line_text.match_indices(marker) {
                    let byte_after_marker = line_text.as_bytes().get(found_index + marker.len());
                    assert!(
                        !matches!(byte_after_marker, Some(byte) if byte.is_ascii_digit()),
                        "{}:{}: hard-coded error-code number: {}",
                        file_name,
                        line_index + 1,
                        line_text.trim()
                    );
                }
            }
        }
    }

    /// `USAGE_TEXT` is a static string (no heap, no formatting), so it cannot
    /// read `MAX_TOP_N` or `DEFAULT_TOP_N` directly. This test keeps it in
    /// step with those constants: changing a constant without updating the
    /// usage text fails here.
    #[test]
    fn guard_usage_text_matches_top_n_constants() {
        let range_text = format!("--top-n 1..{}", MAX_TOP_N);
        let default_text = format!("(default {})", DEFAULT_TOP_N);
        assert!(
            USAGE_TEXT.contains(&range_text),
            "USAGE_TEXT range is stale"
        );
        assert!(
            USAGE_TEXT.contains(&default_text),
            "USAGE_TEXT default is stale"
        );
    }

    /// Loop-scan totals: consistent counters pass; counters that do not add
    /// up (built directly, simulating a forgotten counter) return 407.
    #[test]
    fn ana_check_loop_scan_totals_mismatch_with_code_407() {
        let consistent = LoopScanStatistics {
            files_total: 3,
            files_scanned: 1,
            files_skipped_cold: 2,
            ..LoopScanStatistics::default()
        };
        assert!(check_loop_scan_totals(&consistent, &LoopScanFileNotes::default()).is_ok());

        let inconsistent = LoopScanStatistics {
            files_total: 3,
            files_scanned: 1,
            ..LoopScanStatistics::default()
        };
        let error =
            check_loop_scan_totals(&inconsistent, &LoopScanFileNotes::default()).unwrap_err();
        assert_eq!(error, HeatmapError::AnaLoopScanTotalsMismatch);
        assert_eq!(error.code(), 407);
    }

    /// A source path listed in two `SF:` records is counted once as a duplicate.
    #[test]
    fn ana_count_duplicate_source_paths_counts_repeats() {
        let records = parse_lcov_text(
            "SF:/abs/a.rs\nDA:1,1\nend_of_record\nSF:/abs/b.rs\nDA:1,1\nend_of_record\nSF:/abs/a.rs\nDA:2,1\nend_of_record\n",
        );
        assert_eq!(count_duplicate_source_paths(&records), 1);
        assert_eq!(count_duplicate_source_paths(&parse_sample()), 0);
    }

    /// The cold-tail line derives its ceiling from the last concentration
    /// target (99 -> "<= 1%"), not from typed-in text.
    #[test]
    fn rpt_writeheat_kind_section_cold_tail_uses_last_target() {
        let records = parse_sample();
        let function_sites = vec![make_site(90, 1), make_site(9, 2), make_site(1, 3)];
        let report_text = render_text_report(&records, &function_sites, &[]);
        assert!(report_text.contains("together carry <= 1% of counts"));
    }

    /// Runs the command-line parser on string arguments; returns the error, if any.
    fn cli_error(arguments: &[&str]) -> Option<HeatmapError> {
        let os_arguments: Vec<OsString> = arguments
            .iter()
            .map(|argument| OsString::from(*argument))
            .collect();
        parse_cli_arguments(os_arguments.into_iter()).err()
    }

    #[test]
    fn cli_parse_cli_arguments_extra_pair_with_code_101() {
        let error = cli_error(&[
            "hix",
            "--lcov",
            "/abs/in.lcov",
            "--out-dir",
            "/abs/out",
            "--top-n",
            "5",
            "--run-label",
            "run_005_pumpkin",
            "--run-duration-secs",
            "300",
            "--work-units",
            "1200",
            "--work-unit-name",
            "chunks_generated",
            "--extra",
            "x",
        ])
        .unwrap();
        assert_eq!(error, HeatmapError::CliTooManyArguments);
        assert_eq!(error.code(), 101);
    }

    #[test]
    fn cli_parse_cli_arguments_missing_lcov_with_code_104() {
        let error = cli_error(&["hix", "--out-dir", "/abs/out"]).unwrap();
        assert_eq!(error, HeatmapError::CliMissingLcovPath);
        assert_eq!(error.code(), 104);
    }

    #[test]
    fn cli_parse_cli_arguments_missing_out_dir_with_code_105() {
        let error = cli_error(&["hix", "--lcov", "/abs/in.lcov"]).unwrap();
        assert_eq!(error, HeatmapError::CliMissingOutputDirectory);
        assert_eq!(error.code(), 105);
    }

    #[test]
    fn cli_parse_cli_arguments_top_n_not_a_number_with_code_107() {
        let error = cli_error(&[
            "hix",
            "--lcov",
            "/abs/in.lcov",
            "--out-dir",
            "/abs/out",
            "--top-n",
            "ten",
        ])
        .unwrap();
        assert_eq!(error, HeatmapError::CliTopNNotANumber);
        assert_eq!(error.code(), 107);
    }

    #[test]
    fn cli_parse_cli_arguments_duplicate_flag_with_code_108() {
        let error = cli_error(&["hix", "--lcov", "/abs/a.lcov", "--lcov", "/abs/b.lcov"]).unwrap();
        assert_eq!(error, HeatmapError::CliDuplicateFlag);
        assert_eq!(error.code(), 108);
    }

    #[test]
    fn type_top_n_count_new_zero_via_cli_with_code_150() {
        let error = cli_error(&[
            "hix",
            "--lcov",
            "/abs/in.lcov",
            "--out-dir",
            "/abs/out",
            "--top-n",
            "0",
        ])
        .unwrap();
        assert_eq!(error, HeatmapError::TypeTopNOutOfRange);
        assert_eq!(error.code(), 150);
    }

    /// Invariant catch: a TopNCount corrupted after construction (built
    /// directly, simulating a bit-flip) is rejected by `.get()`.
    #[test]
    fn type_top_n_count_get_corrupted_with_code_151() {
        let corrupted = TopNCount { top_n_value: 0 };
        let error = corrupted.tnc_get().unwrap_err();
        assert_eq!(error, HeatmapError::TypeTopNCorrupted);
        assert_eq!(error.code(), 151);
    }

    /// Invariant catch: a SourceLineNumber corrupted to 0 is rejected by `.get()`.
    #[test]
    fn type_source_line_number_get_corrupted_with_code_153() {
        let corrupted = SourceLineNumber { line_value: 0 };
        let error = corrupted.sln_get().unwrap_err();
        assert_eq!(error, HeatmapError::TypeLineNumberCorrupted);
        assert_eq!(error.code(), 153);
    }

    /// Invariant catch: an AbsolutePath holding a relative path is rejected by `.get()`.
    #[test]
    fn type_absolute_path_get_corrupted_with_code_155() {
        let corrupted = AbsolutePath {
            absolute_path: PathBuf::from("relative/path"),
        };
        let error = corrupted.ap_get().unwrap_err();
        assert_eq!(error, HeatmapError::TypePathCorrupted);
        assert_eq!(error.code(), 155);
    }

    #[test]
    fn lcov_parse_not_utf8_with_code_208() {
        let mut cursor = Cursor::new(b"SF:/abs/a\xff.rs\n".to_vec());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovNotUtf8);
        assert_eq!(error.code(), 208);
    }

    #[test]
    fn lcov_parse_end_of_record_outside_file_with_code_209() {
        let mut cursor = Cursor::new("end_of_record\n".as_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovRecordOutsideFile);
        assert_eq!(error.code(), 209);
    }

    #[test]
    fn lcov_parse_nested_sf_with_code_212() {
        let mut cursor = Cursor::new("SF:/abs/a.rs\nSF:/abs/b.rs\n".as_bytes());
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovMalformedRecord);
        assert_eq!(error.code(), 212);
    }

    #[test]
    fn lcov_parse_fnda_sum_overflow_with_code_216() {
        let mut cursor = Cursor::new(
            "SF:/abs/a.rs\nFNDA:18446744073709551615,f\nFNDA:1,f\nend_of_record\n".as_bytes(),
        );
        let error = parse_lcov_reader(&mut cursor).unwrap_err();
        assert_eq!(error, HeatmapError::LcovCountOverflow);
        assert_eq!(error.code(), 216);
    }

    /// Invariant catch: a site whose file index points past the records.
    #[test]
    fn ana_lookup_source_path_invalid_index_with_code_402() {
        let records = parse_sample();
        let error = lookup_source_path(&records, 99).unwrap_err();
        assert_eq!(error, HeatmapError::AnaFileIndexInvalid);
        assert_eq!(error.code(), 402);
    }
    /// A unique path under the temp dir (not created). Unique per test label,
    /// process, and time, so parallel tests never collide.
    fn unique_temp_path(test_label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hix_test_{}_{}_{}",
            test_label,
            std::process::id(),
            nanos
        ))
    }

    /// Preflight: an existing directory (the temp dir itself) is refused.
    #[test]
    fn rpt_check_output_path_is_new_existing_with_code_510() {
        let error = check_output_path_is_new(&std::env::temp_dir()).unwrap_err();
        assert_eq!(error, HeatmapError::RptOutputPathAlreadyExists);
        assert_eq!(error.code(), 510);
        assert!(error.is_cli_usage_error()); // main shows the usage text
    }

    /// Preflight: a path that does not exist passes (nothing is created).
    #[test]
    fn rpt_check_output_path_is_new_missing_path_passes() {
        let missing_path = unique_temp_path("preflight_missing");
        assert!(check_output_path_is_new(&missing_path).is_ok());
        assert!(!missing_path.exists());
    }

    /// `/` has no parent: refused without touching the filesystem.
    #[test]
    fn rpt_create_new_output_directory_root_with_code_512() {
        let error = create_new_output_directory(Path::new("/")).unwrap_err();
        assert_eq!(error, HeatmapError::RptOutputPathHasNoParent);
        assert_eq!(error.code(), 512);
    }

    /// First create succeeds (parent created too); preflight then refuses
    /// (510); a second create is refused atomically (513).
    #[test]
    fn rpt_create_new_output_directory_twice_with_code_513() {
        let run_directory = unique_temp_path("create_twice");
        let analysis_directory = run_directory.join("analysis_001_test");
        create_new_output_directory(&analysis_directory).unwrap();
        assert!(analysis_directory.is_dir());

        assert_eq!(
            check_output_path_is_new(&analysis_directory).unwrap_err(),
            HeatmapError::RptOutputPathAlreadyExists
        );
        let error = create_new_output_directory(&analysis_directory).unwrap_err();
        assert_eq!(error, HeatmapError::RptOutputDirectoryAppearedDuringRun);
        assert_eq!(error.code(), 513);

        fs::remove_dir(&analysis_directory).unwrap();
        fs::remove_dir(&run_directory).unwrap();
    }

    /// Report files are create-new: a second write is refused (515) and the
    /// first file's content is unchanged.
    #[test]
    fn rpt_write_bytes_to_new_file_existing_with_code_515() {
        let directory = unique_temp_path("no_overwrite");
        fs::create_dir(&directory).unwrap();
        let report_path = directory.join(REPORT_FILE_NAME);

        write_bytes_to_new_file(&report_path, b"first").unwrap();
        let error = write_bytes_to_new_file(&report_path, b"second").unwrap_err();
        assert_eq!(error, HeatmapError::RptOpenAlreadyExists);
        assert_eq!(error.code(), 515);
        assert!(!error.is_retryable()); // fails fast, no backoff sleeps
        assert_eq!(fs::read(&report_path).unwrap(), b"first".to_vec());

        fs::remove_file(&report_path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    /// The usage text states the never-overwrite rule (kept in step with behavior).
    #[test]
    fn guard_usage_text_states_out_dir_must_be_new() {
        assert!(USAGE_TEXT.contains("must not exist yet"));
    }

    /// Listing vs counters: a counted skip with no listed entry returns 408;
    /// a matching listing passes.
    #[test]
    fn ana_check_loop_scan_totals_file_notes_mismatch_with_code_408() {
        let statistics = LoopScanStatistics {
            files_total: 1,
            files_skipped_not_found: 1,
            ..LoopScanStatistics::default()
        };
        let error = check_loop_scan_totals(&statistics, &LoopScanFileNotes::default()).unwrap_err();
        assert_eq!(error, HeatmapError::AnaLoopScanFileNotesMismatch);
        assert_eq!(error.code(), 408);

        let matching_notes = LoopScanFileNotes {
            skipped_files: vec![SkippedFileNote {
                source_file_index: 0,
                reason: FileSkipReason::NotFound,
                error_code: HeatmapError::SrcOpenNotFound.code(),
            }],
            partly_scanned_files: Vec::new(),
        };
        assert!(check_loop_scan_totals(&statistics, &matching_notes).is_ok());
    }

    /// Skip classification: every scan error maps to its counter reason;
    /// unclassified codes fall back to "other error".
    #[test]
    fn src_file_skip_reason_from_scan_error_maps_codes() {
        assert_eq!(
            FileSkipReason::from_scan_error(HeatmapError::TypePathNotAbsolute),
            FileSkipReason::NonAbsolutePath
        );
        assert_eq!(
            FileSkipReason::from_scan_error(HeatmapError::SrcOpenNotFound),
            FileSkipReason::NotFound
        );
        assert_eq!(
            FileSkipReason::from_scan_error(HeatmapError::SrcOpenPermissionDenied),
            FileSkipReason::PermissionDenied
        );
        assert_eq!(
            FileSkipReason::from_scan_error(HeatmapError::SrcLineExceedsSkipCap),
            FileSkipReason::LineExceedsSkipCap
        );
        assert_eq!(
            FileSkipReason::from_scan_error(HeatmapError::SrcTooManyLines),
            FileSkipReason::TooManyLines
        );
        assert_eq!(
            FileSkipReason::from_scan_error(HeatmapError::SrcReadFailed),
            FileSkipReason::OtherError
        );
    }

    /// Cold file: counted only. Relative path and missing file: counted AND
    /// listed, sorted by reason, with their exact codes. Totals checks pass.
    #[test]
    fn src_scan_all_files_for_loops_lists_skipped_files_with_reasons() {
        let records = parse_lcov_text(
            "SF:/abs/hix_test_cold.rs\nDA:1,0\nend_of_record\n\
                 SF:relative/hix_test.rs\nDA:1,5\nend_of_record\n\
                 SF:/nonexistent_hix_test_dir/missing.rs\nDA:1,5\nend_of_record\n",
        );
        let (loop_sites, statistics, file_notes) = scan_all_files_for_loops(&records);
        assert!(loop_sites.is_empty());
        assert_eq!(statistics.files_total, 3);
        assert_eq!(statistics.files_skipped_cold, 1);
        assert_eq!(statistics.files_skipped_non_absolute_path, 1);
        assert_eq!(statistics.files_skipped_not_found, 1);

        assert_eq!(file_notes.skipped_files.len(), 2); // cold file not listed
        assert_eq!(
            file_notes.skipped_files[0].reason,
            FileSkipReason::NonAbsolutePath
        );
        assert_eq!(file_notes.skipped_files[0].source_file_index, 1);
        assert_eq!(file_notes.skipped_files[0].error_code, 154);
        assert_eq!(file_notes.skipped_files[1].reason, FileSkipReason::NotFound);
        assert_eq!(file_notes.skipped_files[1].source_file_index, 2);
        assert_eq!(file_notes.skipped_files[1].error_code, 301);
        assert!(check_loop_scan_totals(&statistics, &file_notes).is_ok());
    }

    /// A real (temp) source file with one over-long line is scanned and
    /// listed as partly scanned with its over-long-line count.
    #[test]
    fn src_scan_all_files_for_loops_lists_partly_scanned_file() {
        let directory = unique_temp_path("partly_scanned");
        fs::create_dir(&directory).unwrap();
        let source_path = directory.join("gen.rs");
        let source_text = format!(
            "fn fill() {{\n    const T: [u8; 1] = [{}];\n    for x in items {{\n    }}\n}}\n",
            "1,".repeat(35 * 1024)
        );
        fs::write(&source_path, source_text).unwrap();

        let lcov_text = format!(
            "SF:{}\nFN:1,_ZN3gen4fill17h0E\nFNDA:5,_ZN3gen4fill17h0E\nDA:1,5\nDA:3,500\nend_of_record\n",
            source_path.display()
        );
        let records = parse_lcov_text(&lcov_text);
        let (loop_sites, statistics, file_notes) = scan_all_files_for_loops(&records);
        assert_eq!(loop_sites.len(), 1);
        assert_eq!(statistics.files_scanned, 1);
        assert_eq!(statistics.files_with_overlong_source_lines, 1);
        assert!(file_notes.skipped_files.is_empty());
        assert_eq!(file_notes.partly_scanned_files.len(), 1);
        assert_eq!(file_notes.partly_scanned_files[0].overlong_line_count, 1);
        assert!(check_loop_scan_totals(&statistics, &file_notes).is_ok());

        fs::remove_file(&source_path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    /// Report listing: full totals shown, rows capped at Top-N.
    #[test]
    fn rpt_write_loop_scan_file_notes_caps_rows_at_top_n() {
        let records = parse_sample();
        let skipped_note = SkippedFileNote {
            source_file_index: 0,
            reason: FileSkipReason::NotFound,
            error_code: HeatmapError::SrcOpenNotFound.code(),
        };
        let partly_note = PartlyScannedFileNote {
            source_file_index: 0,
            overlong_line_count: 75,
        };
        let file_notes = LoopScanFileNotes {
            skipped_files: vec![skipped_note; 12],
            partly_scanned_files: vec![partly_note; 3],
        };
        let report_text = render_text_report_with_notes(&records, &[], &[], &file_notes, 10);
        assert!(report_text.contains("[loop-scan file notes]"));
        assert!(report_text.contains("their loops are missing): 12   (showing up to 10)"));
        assert_eq!(report_text.matches("code 301").count(), 10);
        assert!(report_text.contains("rest skipped): 3   (showing up to 10)"));
        assert_eq!(report_text.matches("75 over-long lines").count(), 3);
    }

    /// Converts string arguments to `OsString` arguments.
    fn os_arguments(arguments: &[&str]) -> Vec<OsString> {
        arguments
            .iter()
            .map(|argument| OsString::from(*argument))
            .collect()
    }

    /// All seven flags (any order) produce a configuration with run metadata.
    #[test]
    fn cli_parse_cli_arguments_accepts_all_seven_flags() {
        let configuration = parse_cli_arguments(
            os_arguments(&[
                "hix",
                "--work-unit-name",
                "chunks_generated",
                "--lcov",
                "/abs/in.lcov",
                "--run-duration-secs",
                "300",
                "--out-dir",
                "/abs/out",
                "--work-units",
                "1200",
                "--top-n",
                "5",
                "--run-label",
                "run_005_pumpkin",
            ])
            .into_iter(),
        )
        .unwrap();
        let run_metadata = &configuration.run_metadata;
        assert_eq!(
            run_metadata.run_label.as_ref().unwrap().rl_get().unwrap(),
            "run_005_pumpkin"
        );
        assert_eq!(run_metadata.run_duration.unwrap().rds_get().unwrap(), 300);
        let work_units = run_metadata.work_units.as_ref().unwrap();
        assert_eq!(work_units.count.wuc_get().unwrap(), 1200);
        assert_eq!(work_units.name.wun_get().unwrap(), "chunks_generated");
    }

    /// Without metadata flags, metadata is empty (all optional).
    #[test]
    fn cli_parse_cli_arguments_metadata_absent_is_default() {
        let configuration = parse_cli_arguments(
            os_arguments(&["hix", "--lcov", "/abs/in.lcov", "--out-dir", "/abs/out"]).into_iter(),
        )
        .unwrap();
        assert_eq!(configuration.run_metadata, RunMetadata::default());
    }

    #[test]
    fn cli_parse_cli_arguments_run_duration_not_a_number_with_code_111() {
        let error = cli_error(&[
            "hix",
            "--lcov",
            "/abs/in.lcov",
            "--out-dir",
            "/abs/out",
            "--run-duration-secs",
            "five",
        ])
        .unwrap();
        assert_eq!(error, HeatmapError::CliRunDurationNotANumber);
        assert_eq!(error.code(), 111);
    }

    #[test]
    fn cli_parse_cli_arguments_work_units_without_name_with_code_115() {
        let error = cli_error(&[
            "hix",
            "--lcov",
            "/abs/in.lcov",
            "--out-dir",
            "/abs/out",
            "--work-units",
            "10",
        ])
        .unwrap();
        assert_eq!(error, HeatmapError::CliWorkUnitsWithoutName);
        assert_eq!(error.code(), 115);
    }

    #[test]
    fn cli_parse_cli_arguments_work_unit_name_without_units_with_code_116() {
        let error = cli_error(&[
            "hix",
            "--lcov",
            "/abs/in.lcov",
            "--out-dir",
            "/abs/out",
            "--work-unit-name",
            "ticks",
        ])
        .unwrap();
        assert_eq!(error, HeatmapError::CliWorkUnitNameWithoutUnits);
        assert_eq!(error.code(), 116);
    }

    #[test]
    fn type_run_label_new_invalid_with_code_156() {
        for bad_label in ["", "run 005", "run/005", "run\t005"] {
            let error = RunLabel::rl_new(bad_label).unwrap_err();
            assert_eq!(error, HeatmapError::TypeRunLabelInvalid);
            assert_eq!(error.code(), 156);
        }
        let too_long = "x".repeat(MAX_RUN_LABEL_BYTES + 1);
        assert_eq!(
            RunLabel::rl_new(&too_long).unwrap_err(),
            HeatmapError::TypeRunLabelInvalid
        );
        assert_eq!(
            RunLabel::rl_new("run_005_pumpkin.v2-a")
                .unwrap()
                .rl_get()
                .unwrap(),
            "run_005_pumpkin.v2-a"
        );
    }

    #[test]
    fn type_run_label_get_corrupted_with_code_157() {
        let corrupted = RunLabel {
            run_label_text: String::from("bad label"),
        };
        let error = corrupted.rl_get().unwrap_err();
        assert_eq!(error, HeatmapError::TypeRunLabelCorrupted);
        assert_eq!(error.code(), 157);
    }

    #[test]
    fn type_run_duration_seconds_new_out_of_range_with_code_158() {
        let error = RunDurationSeconds::rds_new(0).unwrap_err();
        assert_eq!(error, HeatmapError::TypeRunDurationOutOfRange);
        assert_eq!(error.code(), 158);
        assert_eq!(
            RunDurationSeconds::rds_new(MAX_RUN_DURATION_SECS + 1).unwrap_err(),
            HeatmapError::TypeRunDurationOutOfRange
        );
        assert_eq!(
            RunDurationSeconds::rds_new(300).unwrap().rds_get().unwrap(),
            300
        );
    }

    #[test]
    fn type_run_duration_seconds_get_corrupted_with_code_159() {
        let corrupted = RunDurationSeconds {
            duration_seconds: 0,
        };
        let error = corrupted.rds_get().unwrap_err();
        assert_eq!(error, HeatmapError::TypeRunDurationCorrupted);
        assert_eq!(error.code(), 159);
    }

    #[test]
    fn type_work_unit_count_new_out_of_range_with_code_160() {
        let error = WorkUnitCount::wuc_new(0).unwrap_err();
        assert_eq!(error, HeatmapError::TypeWorkUnitsOutOfRange);
        assert_eq!(error.code(), 160);
        assert_eq!(
            WorkUnitCount::wuc_new(MAX_WORK_UNITS + 1).unwrap_err(),
            HeatmapError::TypeWorkUnitsOutOfRange
        );
    }

    #[test]
    fn type_work_unit_count_get_corrupted_with_code_161() {
        let corrupted = WorkUnitCount { work_unit_count: 0 };
        let error = corrupted.wuc_get().unwrap_err();
        assert_eq!(error, HeatmapError::TypeWorkUnitsCorrupted);
        assert_eq!(error.code(), 161);
    }

    #[test]
    fn type_work_unit_name_new_invalid_with_code_162() {
        let error = WorkUnitName::wun_new("chunks generated").unwrap_err();
        assert_eq!(error, HeatmapError::TypeWorkUnitNameInvalid);
        assert_eq!(error.code(), 162);
        let too_long = "x".repeat(MAX_WORK_UNIT_NAME_BYTES + 1);
        assert_eq!(
            WorkUnitName::wun_new(&too_long).unwrap_err(),
            HeatmapError::TypeWorkUnitNameInvalid
        );
    }

    #[test]
    fn type_work_unit_name_get_corrupted_with_code_163() {
        let corrupted = WorkUnitName {
            work_unit_name_text: String::from("bad\tname"),
        };
        let error = corrupted.wun_get().unwrap_err();
        assert_eq!(error, HeatmapError::TypeWorkUnitNameCorrupted);
        assert_eq!(error.code(), 163);
    }

    /// With all metadata: provenance lines, per-minute figure, and the
    /// appended TSV column (header + 11 fields per row, value = count / units).
    #[test]
    fn rpt_run_metadata_in_provenance_and_tsv_column() {
        let records = parse_sample();
        let function_sites = vec![make_site(2400, 1)];
        let run_metadata = RunMetadata {
            run_label: Some(RunLabel::rl_new("run_005_pumpkin").unwrap()),
            run_duration: Some(RunDurationSeconds::rds_new(300).unwrap()),
            work_units: Some(WorkUnits {
                count: WorkUnitCount::wuc_new(1200).unwrap(),
                name: WorkUnitName::wun_new("chunks_generated").unwrap(),
            }),
        };
        let (report_text, tsv_text) = render_reports(
            &records,
            &function_sites,
            &[],
            &LoopScanFileNotes::default(),
            &run_metadata,
            10,
        );
        assert!(report_text.contains("run label               : run_005_pumpkin"));
        assert!(report_text.contains("run duration            : 300 s (5.00 min)"));
        assert!(report_text.contains("work units              : 1200 chunks_generated"));
        assert!(report_text.contains("work units per minute   : 240.00 chunks_generated/min"));

        let mut tsv_lines = tsv_text.lines();
        assert!(tsv_lines.next().unwrap().ends_with("\tcount_per_work_unit"));
        let data_row = tsv_lines.next().unwrap();
        assert_eq!(data_row.split('\t').count(), 11);
        assert!(data_row.ends_with("\t2.000000")); // 2400 / 1200
    }

    /// Without metadata: "(not given)" lines, and the TSV keeps 10 columns.
    #[test]
    fn rpt_run_metadata_absent_prints_not_given_and_no_tsv_column() {
        let records = parse_sample();
        let function_sites = vec![make_site(2400, 1)];
        let (report_text, tsv_text) = render_reports(
            &records,
            &function_sites,
            &[],
            &LoopScanFileNotes::default(),
            &RunMetadata::default(),
            10,
        );
        assert!(report_text.contains("run label               : (not given)"));
        assert!(report_text.contains("run duration            : (not given)"));
        assert!(report_text.contains("work units              : (not given)"));
        assert!(report_text.contains("work units per minute   : n/a"));
        let mut tsv_lines = tsv_text.lines();
        assert!(tsv_lines.next().unwrap().ends_with("\tper_enclosing_call"));
        assert_eq!(tsv_lines.next().unwrap().split('\t').count(), 10);
    }

    /// `USAGE_TEXT` is static, so it cannot read the metadata constants;
    /// this keeps it in step with them.
    #[test]
    fn guard_usage_text_matches_run_metadata_constants() {
        assert!(USAGE_TEXT.contains(&format!("(1..{})", MAX_RUN_DURATION_SECS)));
        assert!(USAGE_TEXT.contains(&format!("(1..{})", MAX_WORK_UNITS)));
        assert!(USAGE_TEXT.contains(&format!("1-{} characters", MAX_RUN_LABEL_BYTES)));
        assert!(USAGE_TEXT.contains(&format!("unit name: 1-{}", MAX_WORK_UNIT_NAME_BYTES)));
    }

    /// Builds sites hottest-first from counts (lines 1, 2, ...) and their summary.
    fn sorted_sites_and_summary(counts: &[u64]) -> (Vec<HeatSite>, HeatKindSummary) {
        let mut sites: Vec<HeatSite> = counts
            .iter()
            .enumerate()
            .map(|(index, count)| make_site(*count, (index as u32) + 1))
            .collect();
        let summary = sort_and_summarize_sites(&mut sites).unwrap();
        (sites, summary)
    }

    /// Gini by hand: counts [3, 1] -> sum(i * x_i) = 1*1 + 2*3 = 7,
    /// G = 2*7 / (2*4) - 3/2 = 0.25.
    #[test]
    fn ana_compute_distribution_shape_gini_known_value() {
        let (sites, summary) = sorted_sites_and_summary(&[3, 1]);
        let shape = compute_distribution_shape(&sites, &summary).unwrap();
        assert!((shape.gini_all_sites.unwrap() - 0.25).abs() < 1e-12);
        assert!((shape.gini_counted_sites.unwrap() - 0.25).abs() < 1e-12);
    }

    /// Equal counts: Gini 0, shares by site count, no gap, no drop.
    #[test]
    fn ana_compute_distribution_shape_equal_counts() {
        let (sites, summary) = sorted_sites_and_summary(&[5, 5, 5, 5]);
        let shape = compute_distribution_shape(&sites, &summary).unwrap();
        assert!(shape.gini_all_sites.unwrap().abs() < 1e-12);
        assert!((shape.top_narrow_share_percent.unwrap() - 25.0).abs() < 1e-9);
        assert!((shape.top_wide_share_percent.unwrap() - 100.0).abs() < 1e-9);
        assert!(shape.largest_empty_decade_gap.is_none());
        assert!(shape.largest_head_drop.is_none());
    }

    /// One counted site among zeros: Gini over all sites (n-1)/n = 0.75;
    /// over counted sites 0.0 (a single site is perfectly "equal").
    #[test]
    fn ana_compute_distribution_shape_one_hot_site_among_zeros() {
        let (sites, summary) = sorted_sites_and_summary(&[0, 100, 0, 0]);
        let shape = compute_distribution_shape(&sites, &summary).unwrap();
        assert!((shape.gini_all_sites.unwrap() - 0.75).abs() < 1e-12);
        assert!(shape.gini_counted_sites.unwrap().abs() < 1e-12);
        assert!((shape.top_narrow_share_percent.unwrap() - 100.0).abs() < 1e-9);
    }

    /// Counts 5_000_000 (bucket 7) and 3 (bucket 1): buckets 2..=6 are empty,
    /// a gap of 5 decades: no sites in [1e1, 1e6).
    #[test]
    fn ana_find_largest_empty_decade_gap_detects_gap() {
        let (_sites, summary) = sorted_sites_and_summary(&[5_000_000, 3]);
        let gap = find_largest_empty_decade_gap(&summary.decade_histogram).unwrap();
        assert_eq!(
            gap,
            EmptyDecadeGap {
                empty_decade_count: 5,
                lower_bucket_index: 1,
                upper_bucket_index: 7,
            }
        );
    }

    /// Head = sites carrying 99% of counts (all 3 here). Ratios 10x and 2x:
    /// the largest drop is rank 1 -> 2, 10x.
    #[test]
    fn ana_find_largest_head_drop_picks_largest_ratio() {
        let (sites, summary) = sorted_sites_and_summary(&[1000, 100, 50]);
        assert_eq!(summary.sites_reaching_percent[2], 3);
        let drop = find_largest_head_drop(&sites, 3).unwrap();
        assert_eq!(drop.higher_position, 0);
        assert!((drop.drop_ratio - 10.0).abs() < 1e-12);
    }

    /// Unsorted input is rejected (sites built directly, bypassing the sort).
    #[test]
    fn ana_compute_distribution_shape_unsorted_with_code_409() {
        let sites = vec![make_site(1, 1), make_site(9, 2)];
        let summary = summarize_sorted_sites(&sites).unwrap();
        let error = compute_distribution_shape(&sites, &summary).unwrap_err();
        assert_eq!(error, HeatmapError::AnaShapeInputNotSorted);
        assert_eq!(error.code(), 409);
    }

    /// Report: section, legend, and figures present; an empty kind prints n/a.
    #[test]
    fn rpt_write_distribution_shape_section_renders() {
        let records = parse_sample();
        let (function_sites, _summary) = sorted_sites_and_summary(&[1000, 100, 50]);
        let report_text = render_text_report(&records, &function_sites, &[]);
        assert!(report_text.contains("[DISTRIBUTION SHAPE]  (experimental"));
        assert!(report_text.contains("gini, all sites"));
        assert!(report_text.contains("top-10 share"));
        assert!(report_text.contains("largest drop within 99% head"));
        assert!(report_text.contains("10.0000x  rank 1 -> 2  (count 1000 -> 100)"));
        assert!(report_text.contains("  LOOPS\n    n/a (total count is 0)"));
    }

    // ------------------------------------------------------------------
    // HIX config files
    // ------------------------------------------------------------------

    /// A complete, valid config. Paths need not exist: config files store
    /// paths; they do not check them.
    fn sample_config(work_unit_name: Option<&str>) -> HixConfig {
        HixConfig {
            target_crate_path: ConfigPath::cp_new(Path::new("/home/user/code/Pumpkin")).unwrap(),
            target_binary_name: CargoBinaryName::ntk_new("pumpkin").unwrap(),
            modeling_data_path: ConfigPath::cp_new(Path::new(
                "/home/user/code/hix_heatmap_indices_for_compute/modeling_data",
            ))
            .unwrap(),
            scenario_name: ScenarioName::ntk_new("pumpkin_world_spawn").unwrap(),
            analysis_purpose: AnalysisPurpose::ntk_new("count_baseline").unwrap(),
            top_n: TopNCount::tnc_new(15).unwrap(),
            work_unit_name: work_unit_name.map(|name| WorkUnitName::wun_new(name).unwrap()),
            demangle_outputs: true,
        }
    }

    /// Renders a config into a `String` (heap is fine in tests).
    fn render_config_to_string(config: &HixConfig) -> String {
        let mut buffer = vec![0u8; CONFIG_FILE_MAX_BYTES];
        let rendered_bytes = render_config_file_text(config, &mut buffer).unwrap();
        String::from_utf8(rendered_bytes.to_vec()).unwrap()
    }

    /// Writes `config_text` to `hix_test.toml` in a new unique temp directory.
    /// Returns the directory (for cleanup) and the file path.
    fn write_temp_config_text(test_label: &str, config_text: &str) -> (PathBuf, AbsolutePath) {
        let directory = unique_temp_path(test_label);
        fs::create_dir(&directory).unwrap();
        let file_path = directory.join("hix_test.toml");
        fs::write(&file_path, config_text).unwrap();
        (directory, AbsolutePath::ap_new(file_path).unwrap())
    }

    /// Removes a config file and its temp directory.
    fn remove_temp_config(directory: &Path, config_file_path: &AbsolutePath) {
        fs::remove_file(config_file_path.ap_get().unwrap()).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    /// Each name kind rejects text outside its rule with its own code, so a
    /// failure names the field: empty, a space, a slash, and one byte over
    /// the kind's maximum. A name at exactly the maximum is accepted.
    #[test]
    fn type_name_text_new_invalid_with_codes_164_166_168() {
        for bad_text in ["", "world spawn", "world/spawn"] {
            assert_eq!(
                ScenarioName::ntk_new(bad_text).unwrap_err(),
                HeatmapError::TypeScenarioNameInvalid
            );
            assert_eq!(
                CargoBinaryName::ntk_new(bad_text).unwrap_err(),
                HeatmapError::TypeCargoBinaryNameInvalid
            );
            assert_eq!(
                AnalysisPurpose::ntk_new(bad_text).unwrap_err(),
                HeatmapError::TypeAnalysisPurposeInvalid
            );
        }
        assert_eq!(HeatmapError::TypeScenarioNameInvalid.code(), 164);
        assert_eq!(HeatmapError::TypeCargoBinaryNameInvalid.code(), 166);
        assert_eq!(HeatmapError::TypeAnalysisPurposeInvalid.code(), 168);

        assert!(ScenarioName::ntk_new(&"s".repeat(MAX_SCENARIO_NAME_BYTES)).is_ok());
        assert_eq!(
            ScenarioName::ntk_new(&"s".repeat(MAX_SCENARIO_NAME_BYTES + 1)).unwrap_err(),
            HeatmapError::TypeScenarioNameInvalid
        );
        assert_eq!(
            CargoBinaryName::ntk_new(&"b".repeat(MAX_CARGO_BINARY_NAME_BYTES + 1)).unwrap_err(),
            HeatmapError::TypeCargoBinaryNameInvalid
        );
        assert_eq!(
            AnalysisPurpose::ntk_new(&"p".repeat(MAX_ANALYSIS_PURPOSE_BYTES + 1)).unwrap_err(),
            HeatmapError::TypeAnalysisPurposeInvalid
        );
    }

    /// Invariant catch: names corrupted after construction (built directly,
    /// bypassing `new`) are rejected by `get` with each kind's own code.
    #[test]
    fn type_name_text_get_corrupted_with_codes_165_167_169() {
        let scenario: ScenarioName = NameText {
            name_text: String::from("bad name"),
            kind: PhantomData,
        };
        let binary: CargoBinaryName = NameText {
            name_text: String::new(),
            kind: PhantomData,
        };
        let purpose: AnalysisPurpose = NameText {
            name_text: String::from("bad/purpose"),
            kind: PhantomData,
        };
        assert_eq!(scenario.ntk_get().unwrap_err().code(), 165);
        assert_eq!(binary.ntk_get().unwrap_err().code(), 167);
        assert_eq!(purpose.ntk_get().unwrap_err().code(), 169);
    }

    /// Path field values: relative paths are refused (817). Non-UTF-8 paths,
    /// quotes, backslashes, control bytes, and over-long paths are refused
    /// (818), because they could not be written and read back unchanged. The
    /// longest storable path is accepted, and the accessor returns the path's
    /// own characters.
    #[test]
    fn cfg_config_field_path_new_rejects_with_codes_817_818() {
        let error = ConfigFieldPath::new(Path::new("relative/crate")).unwrap_err();
        assert_eq!(error, HeatmapError::CfgPathNotAbsolute);
        assert_eq!(error.code(), 817);

        for bad_text in [
            "/home/user/a\"b",
            "/home/user/a\\b",
            "/home/user/a\nb",
            "/home/user/a\tb",
        ] {
            let error = ConfigFieldPath::new(Path::new(bad_text)).unwrap_err();
            assert_eq!(error, HeatmapError::CfgPathValueInvalid, "{:?}", bad_text);
            assert_eq!(error.code(), 818);
        }

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let non_utf8_path = Path::new(std::ffi::OsStr::from_bytes(b"/home/user/a\xffb"));
            assert_eq!(
                ConfigFieldPath::new(non_utf8_path).unwrap_err(),
                HeatmapError::CfgPathValueInvalid
            );
        }

        let longest_path = format!("/{}", "a".repeat(MAX_CONFIG_PATH_BYTES - 1));
        assert!(ConfigFieldPath::new(Path::new(&longest_path)).is_ok());
        let one_byte_over = format!("/{}", "a".repeat(MAX_CONFIG_PATH_BYTES));
        assert_eq!(
            ConfigFieldPath::new(Path::new(&one_byte_over)).unwrap_err(),
            HeatmapError::CfgPathValueInvalid
        );

        let field_path = ConfigFieldPath::new(Path::new("/home/user/code")).unwrap();
        assert_eq!(field_path.get_path_str().unwrap(), "/home/user/code");
    }

    /// Invariant catch: a path value corrupted after construction (relative,
    /// or holding a quote; built directly, bypassing `new`) is rejected by
    /// `get_path_str` with 819.
    #[test]
    fn cfg_config_field_path_get_path_str_corrupted_with_code_819() {
        for corrupted_text in ["relative/path", "/home/a\"b"] {
            let corrupted = ConfigFieldPath {
                field_path_text: String::from(corrupted_text),
            };
            let error = corrupted.get_path_str().unwrap_err();
            assert_eq!(error, HeatmapError::CfgPathValueCorrupted);
            assert_eq!(error.code(), 819);
        }
    }

    /// The written layout is fixed, so config files written by different HIX
    /// runs look the same and can be compared and hand-read.
    ///
    /// The expected text is built with `concat!`, one literal per line, so the
    /// test cannot be broken by re-indenting the source (a string-continuation
    /// literal would take on any indentation added by an editor or formatter).
    #[test]
    fn cfg_render_config_file_text_matches_layout() {
        let expected_text = concat!(
            "# HIX config file (TOML subset: one `key = value` per line, top level only).\n",
            "# Written by HIX. Hand edits are allowed; values may not contain double quotes or backslashes.\n",
            "hix_config_version = 1\n",
            "target_crate_path = \"/home/user/code/Pumpkin\"\n",
            "target_binary_name = \"pumpkin\"\n",
            "modeling_data_path = \"/home/user/code/hix_heatmap_indices_for_compute/modeling_data\"\n",
            "scenario_name = \"pumpkin_world_spawn\"\n",
            "analysis_purpose = \"count_baseline\"\n",
            "top_n = 15\n",
            "work_unit_name = \"chunks_generated\"\n",
            "demangle_outputs = true\n",
        );
        assert_eq!(
            render_config_to_string(&sample_config(Some("chunks_generated"))),
            expected_text
        );
    }

    /// `CONFIG_KEYS` and the writer stay in step: with every field set, each
    /// key is written on exactly one line. A key added to one and not the
    /// other fails here.
    #[test]
    fn cfg_render_config_file_text_writes_every_key_once() {
        let rendered_text = render_config_to_string(&sample_config(Some("chunks_generated")));
        let key_line_total = rendered_text
            .lines()
            .filter(|line| !line.starts_with('#'))
            .count();
        assert_eq!(key_line_total, CONFIG_KEY_COUNT);
        for config_key in CONFIG_KEYS.iter() {
            let key_prefix = format!("{} = ", config_key);
            let matching_lines = rendered_text
                .lines()
                .filter(|line| line.starts_with(&key_prefix))
                .count();
            assert_eq!(matching_lines, 1, "key {}", config_key);
        }
    }

    /// An unset optional work-unit name is omitted entirely (absent = not set).
    #[test]
    fn cfg_render_config_file_text_omits_absent_work_unit_name() {
        let rendered_text = render_config_to_string(&sample_config(None));
        assert!(!rendered_text.contains(CONFIG_KEY_WORK_UNIT_NAME));
    }

    /// Rendering into a buffer that is too small returns 820, never a
    /// truncated file.
    #[test]
    fn cfg_render_config_file_text_small_buffer_with_code_820() {
        let mut small_buffer = [0u8; 64];
        let error = render_config_file_text(&sample_config(None), &mut small_buffer).unwrap_err();
        assert_eq!(error, HeatmapError::CfgRenderBufferFull);
        assert_eq!(error.code(), 820);
    }

    /// Write, read back, and compare, with and without the optional field.
    /// A second write to the same path is refused (824), and the existing
    /// file is unchanged: configs are a record and are never overwritten.
    #[test]
    fn cfg_write_new_config_file_round_trip_and_no_overwrite_with_code_824() {
        let directory = unique_temp_path("cfg_round_trip");
        fs::create_dir(&directory).unwrap();
        let with_units_path =
            AbsolutePath::ap_new(directory.join("hix_pumpkin_world_spawn.toml")).unwrap();
        let without_units_path = AbsolutePath::ap_new(directory.join("hix_no_units.toml")).unwrap();

        let config_with_units = sample_config(Some("chunks_generated"));
        write_new_config_file(&with_units_path, &config_with_units).unwrap();
        assert_eq!(
            load_config_file(&with_units_path).unwrap(),
            config_with_units
        );

        let config_without_units = sample_config(None);
        write_new_config_file(&without_units_path, &config_without_units).unwrap();
        let reloaded = load_config_file(&without_units_path).unwrap();
        assert_eq!(reloaded, config_without_units);
        assert!(reloaded.work_unit_name.is_none());

        let original_bytes = fs::read(with_units_path.ap_get().unwrap()).unwrap();
        let error = write_new_config_file(&with_units_path, &config_without_units).unwrap_err();
        assert_eq!(error, HeatmapError::CfgWriteOpenAlreadyExists);
        assert_eq!(error.code(), 824);
        assert!(!error.is_retryable());
        assert_eq!(
            fs::read(with_units_path.ap_get().unwrap()).unwrap(),
            original_bytes
        );

        fs::remove_file(with_units_path.ap_get().unwrap()).unwrap();
        fs::remove_file(without_units_path.ap_get().unwrap()).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    /// Every field at its maximum length fits `CONFIG_FILE_MAX_BYTES` and the
    /// read buffers, and reads back unchanged. Guards the buffer sizes when
    /// a field or a maximum is changed.
    #[test]
    fn cfg_write_new_config_file_longest_values_round_trip() {
        let longest_path = format!("/{}", "a".repeat(MAX_CONFIG_PATH_BYTES - 1));
        let longest_config = HixConfig {
            target_crate_path: ConfigPath::cp_new(Path::new(&longest_path)).unwrap(),
            target_binary_name: CargoBinaryName::ntk_new(&"b".repeat(MAX_CARGO_BINARY_NAME_BYTES))
                .unwrap(),
            modeling_data_path: ConfigPath::cp_new(Path::new(&longest_path)).unwrap(),
            scenario_name: ScenarioName::ntk_new(&"s".repeat(MAX_SCENARIO_NAME_BYTES)).unwrap(),
            analysis_purpose: AnalysisPurpose::ntk_new(&"p".repeat(MAX_ANALYSIS_PURPOSE_BYTES))
                .unwrap(),
            top_n: TopNCount::tnc_new(MAX_TOP_N).unwrap(),
            work_unit_name: Some(
                WorkUnitName::wun_new(&"w".repeat(MAX_WORK_UNIT_NAME_BYTES)).unwrap(),
            ),
            demangle_outputs: false,
        };
        let directory = unique_temp_path("cfg_longest");
        fs::create_dir(&directory).unwrap();
        let config_file_path = AbsolutePath::ap_new(directory.join("hix_longest.toml")).unwrap();

        write_new_config_file(&config_file_path, &longest_config).unwrap();
        assert_eq!(load_config_file(&config_file_path).unwrap(), longest_config);

        fs::remove_file(config_file_path.ap_get().unwrap()).unwrap();
        fs::remove_dir(&directory).unwrap();
    }

    /// Loading refuses each kind of bad file with its own code. Each case
    /// changes one line of a valid file, so the code is the only difference.
    #[test]
    fn cfg_load_config_file_rejects_invalid_files_with_listed_codes() {
        let valid_text = render_config_to_string(&sample_config(Some("chunks_generated")));
        let cases: [(&str, &str, &str, HeatmapError, u16); 7] = [
            (
                "duplicate key",
                "top_n = 15\n",
                "top_n = 15\ntop_n = 16\n",
                HeatmapError::RSLFDuplicateKey,
                816,
            ),
            (
                "version not a number",
                "hix_config_version = 1\n",
                "hix_config_version = one\n",
                HeatmapError::CfgVersionNotANumber,
                831,
            ),
            (
                "unsupported version",
                "hix_config_version = 1\n",
                "hix_config_version = 2\n",
                HeatmapError::CfgUnsupportedVersion,
                832,
            ),
            (
                "missing required key",
                "scenario_name = \"pumpkin_world_spawn\"\n",
                "",
                HeatmapError::RSLFFieldNotFound,
                811,
            ),
            (
                "relative path",
                "target_crate_path = \"/home/user/code/Pumpkin\"\n",
                "target_crate_path = \"relative/Pumpkin\"\n",
                HeatmapError::CfgPathNotAbsolute,
                817,
            ),
            (
                "top_n out of range",
                "top_n = 15\n",
                "top_n = 0\n",
                HeatmapError::CfgTopNInvalid,
                833,
            ),
            (
                "bad boolean",
                "demangle_outputs = true\n",
                "demangle_outputs = yes\n",
                HeatmapError::CfgBooleanInvalid,
                834,
            ),
        ];
        for (
            case_index,
            (case_label, original_line, replacement_text, expected_error, expected_code),
        ) in cases.iter().enumerate()
        {
            assert!(
                valid_text.contains(original_line),
                "{}: line to change is missing",
                case_label
            );
            let bad_text = valid_text.replacen(original_line, replacement_text, 1);
            let (directory, config_file_path) =
                write_temp_config_text(&format!("cfg_load_reject_{}", case_index), &bad_text);
            let error = load_config_file(&config_file_path).unwrap_err();
            remove_temp_config(&directory, &config_file_path);
            assert_eq!(error, *expected_error, "{}", case_label);
            assert_eq!(error.code(), *expected_code, "{}", case_label);
        }
    }

    /// Hand edits that stay within the format are accepted: spaces around
    /// numbers and booleans, extra comments and blank lines, and unknown keys.
    #[test]
    fn cfg_load_config_file_accepts_hand_edited_spacing_and_comments() {
        let valid_text = render_config_to_string(&sample_config(None));
        let edited_text = valid_text
            .replacen("top_n = 15\n", "top_n =   15  \n", 1)
            .replacen(
                "demangle_outputs = true\n",
                "\n# note\ndemangle_outputs = true \n",
                1,
            )
            + "unknown_future_key = \"ignored\"\n";
        let (directory, config_file_path) = write_temp_config_text("cfg_hand_edited", &edited_text);
        let loaded = load_config_file(&config_file_path).unwrap();
        remove_temp_config(&directory, &config_file_path);
        assert_eq!(loaded, sample_config(None));
    }

    /// The config file name is `hix_<scenario>.toml`.
    #[test]
    fn cfg_config_file_name_for_scenario_builds_name() {
        let scenario_name = ScenarioName::ntk_new("pumpkin_world_spawn").unwrap();
        assert_eq!(
            config_file_name_for_scenario(&scenario_name).unwrap(),
            "hix_pumpkin_world_spawn.toml"
        );
    }
}
