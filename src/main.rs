#![forbid(unsafe_code)]
//! main.rs
//! Binary entry point for hix_heatmap_indices_for_compute (binary name: `hix`).
//!
//! This file is the Tier-3 ("macro") recovery level for a one-shot CLI:
//! any error that propagates up to here is reported as a numeric code only
//! (no paths, no user data), appended to an error log next to the
//! executable, and the process exits with a non-zero status. No panic.
//!
//! # Run guide (count-heat)
//!
//! Run each command separately, one per step. None of these commands change
//! shell environment variables or configuration files.
//!
//! ## One-time setup (third-party tools)
//! ```text
//! rustup component add llvm-tools-preview
//! cargo install cargo-llvm-cov
//! cargo install rustfilt
//! ```
//!
//! ## Folder naming (all run data lives in `modeling_data/`, which is git-ignored)
//! - One folder per run of the target program: `modeling_data/run_NNN_<scenario>/`
//! - One folder per analysis of that run, inside it: `analysis_NNN_<purpose>/`
//! - Numbers are never reused. HIX refuses an existing `--out-dir` (code 510).
//!
//! ## 1. Build HIX (in the HIX crate directory)
//! ```text
//! cargo test
//! cargo build --release
//! ```
//!
//! ## 2. Instrumented run of the target program (in the target crate directory)
//! ```text
//! cargo llvm-cov clean --workspace
//! cargo llvm-cov run --release --no-report --bin <TARGET_BINARY>
//! ```
//! Use the program for the chosen scenario, then stop it cleanly (for
//! Pumpkin: type `stop` in its console). The coverage data is written on a
//! clean exit. Do not paste further commands while the program is running:
//! the program, not the shell, receives them.
//!
//! ## 3. Create the run folder (`mkdir` without `-p`: an existing name is an error)
//! ```text
//! mkdir /ABSOLUTE/hix_heatmap_indices_for_compute/modeling_data/run_NNN_<scenario>
//! ```
//!
//! ## 4. Export the LCOV file (in the target crate directory)
//! ```text
//! cargo llvm-cov report --release --lcov --output-path /ABSOLUTE/hix_heatmap_indices_for_compute/modeling_data/run_NNN_<scenario>/run_NNN_<scenario>.lcov
//! ```
//!
//! ## 5. Analyze (in the HIX crate directory)
//! ```text
//! ./target/release/hix --lcov /ABSOLUTE/.../run_NNN_<scenario>/run_NNN_<scenario>.lcov --out-dir /ABSOLUTE/.../run_NNN_<scenario>/analysis_NNN_<purpose> --top-n 20
//! ```
//! Optional flags: `--run-label`, `--run-duration-secs`, and
//! `--work-units` with `--work-unit-name` (see the usage text).
//!
//! ## 6. Demangle names in the report and TSV (not the .lcov input)
//! ```text
//! rustfilt -i /ABSOLUTE/.../analysis_NNN_<purpose>/hix_report.txt -o /ABSOLUTE/.../analysis_NNN_<purpose>/hix_report.demangled.txt
//! rustfilt -i /ABSOLUTE/.../analysis_NNN_<purpose>/hix_sites.tsv -o /ABSOLUTE/.../analysis_NNN_<purpose>/hix_sites.demangled.tsv
//! ```
//! HIX parses mangled names; demangling first would collapse distinct
//! monomorphized instances into one name (see "duplicate FN names").
//!
//! # Tool choice for time measurement: Linux `perf` (not samply)
//!
//! Count-heat comes from exact LLVM coverage counters. Time-heat must come
//! from sampling a separate, non-instrumented build, because coverage
//! counters change the timing of the code they measure. HIX uses Linux
//! `perf` for this sampling, for these reasons:
//!
//! 1. Direct source: `perf` is the kernel's own front end to `perf_events`,
//!    maintained with the Linux kernel and packaged by Fedora. samply also
//!    uses `perf_events` on Linux, so it adds a layer, not a capability.
//! 2. Plain-text output, parsed with std only: `perf script` prints one
//!    sample per line, with fields selected explicitly (`-F`), which fixes the
//!    format HIX parses. samply writes Firefox-Profiler (Gecko) JSON, which
//!    would need a JSON parser (a crate, or a hand-written one) and ties HIX
//!    to that format and its viewer.
//! 3. Measurement control: sampling frequency (`-F`), events (`-e`), and call
//!    graphs from frame pointers (`--call-graph fp`, with the target built
//!    using `-C force-frame-pointers=yes`). Frame-pointer unwinding is cheap
//!    and bounded; DWARF unwinding (large stack copies per sample) is avoided.
//! 4. Hardware counters: `perf` exposes cache misses, branch misses, and
//!    similar events. These matter for the hot-region analysis HIX aims at,
//!    beyond plain time.
//! 5. Auditability: a `perf.data` recording can be kept with a run folder
//!    and re-read later with the same tool.
//!
//! Costs of this choice: `perf` is Linux-only, and sampling by a normal user
//! depends on the `kernel.perf_event_paranoid` setting. HIX reports this
//! setting; it never changes system settings. samply remains an option for
//! cross-platform use or interactive viewing; it is not a dependency of HIX.

/*
# Manual Report Generation Instructions

# 0. One-time setup step: install these third-party tools (unavoidable for v1)
install rustup by their (very sadly curl-based) official install

https://rustup.rs/

Cli install:
```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo install rustfilt
```

# 1. Build the analyzer
    (Template Code)
    cd /home/YOU/code/hix_heatmap_indices_for_compute && cargo test && cargo build --release

### e.g. For PumpkinMC
(Template Pseudo Code)
```bash
cd /home/YOU/code/Pumpkin
cargo llvm-cov clean --workspace
cargo llvm-cov run --release --no-report --bin pumpkin
#   ... exercise the server with a written-down scenario + duration,
#   ... then stop it using console `stop`, so the .profraw is written
cargo llvm-cov report --release --lcov --output-path /home/YOU/hix/pumpkin_run1.lcov

E.g. in the tested-project Rust crate dir:
```bash
cargo llvm-cov clean --workspace
cargo llvm-cov run --release --no-report --bin pumpkin
# use program, and stop, then... (note, for next line, the path to the lcov file must already exist)
cargo llvm-cov report --release --lcov --output-path /home/oops/code/hix_heatmap_indices_for_compute/modeling_data/test_5/run_005_pumpkin.lcov
```

### Then, back to HIX dir:
Note: '--out-dir' must NOT already exist (HIX never overwrites: code 510). Use a new analysis_NNN_ name per analysis.
```
cargo run --release -- \
  --lcov /home/oops/code/hix_heatmap_indices_for_compute/modeling_data/test_5/run_005_pumpkin.lcov \
  --out-dir /home/oops/code/hix_heatmap_indices_for_compute/modeling_data/test_5/analysis_0010_distribution_shape \
  --top-n 15
```

### Demangle .txt and .tsv (NOT .lcov)

TXT->x
```
rustfilt < /home/oops/code/hix_heatmap_indices_for_compute/modeling_data/test_5/analysis_0010_distribution_shape/hix_report.txt \
        > /home/oops/code/hix_heatmap_indices_for_compute/modeling_data/test_5/analysis_0010_distribution_shape/hix_report.demangled.txt
```

TSV->
```
rustfilt < /home/oops/code/hix_heatmap_indices_for_compute/modeling_data/test_5/analysis_005_count_baseline/hix_sites.tsv \
        > /home/oops/code/hix_heatmap_indices_for_compute/modeling_data/test_5/analysis_005_count_baseline/hix_sites.demangled.tsv
```

*/

mod hix_heatmap_indices_for_compute;
use hix_heatmap_indices_for_compute::{USAGE_TEXT, append_error_code_to_log, run_heatmap_cli};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run_heatmap_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error_code) => {
            // Numeric code only: safe in all modes (no heap, no PII).
            eprintln!(
                "hix_heatmap_indices_for_compute: failed with error code {}",
                error_code.code()
            );

            // Debug mode: human-readable description (Display exists only in debug/test).
            #[cfg(debug_assertions)]
            eprintln!(
                "hix_heatmap_indices_for_compute: debug detail: {}",
                error_code
            );

            // Command-line mistakes are user-fixable: show usage text (static, no heap).
            if error_code.is_cli_usage_error() {
                eprintln!("{}", USAGE_TEXT);
            }

            // Log the code; if logging itself fails, say so with its own code.
            if let Err(log_error_code) = append_error_code_to_log(error_code) {
                eprintln!(
                    "hix_heatmap_indices_for_compute: error log unavailable, error code {}",
                    log_error_code.code()
                );
            }
            ExitCode::FAILURE
        }
    }
}
