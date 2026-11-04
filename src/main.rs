//! asd2mp4 CLI + minimal interactive menu.
//! Core demux/convert logic lives in the library crate (src/lib.rs);
//! the Windows GUI is a separate binary (src/bin/asd2gui.rs).

use asd2mp4::{run_batch, Opts};
use std::env;
use std::path::PathBuf;

fn usage() {
    eprintln!(
        "asd2mp4 <input.asd|dir> <output_dir> [--channel 0|1] [--fps N] [--metadata-only]\n\
         (run with no arguments for the interactive menu)"
    );
}

// ---- Minimal interactive UI (std-only, text menu; works on any
// ---- console including Windows cmd/PowerShell) ----
fn prompt(label: &str, default: &str) -> Option<String> {
    use std::io::Write as _;
    print!("{} [{}]: ", label, default);
    std::io::stdout().flush().ok()?;
    let mut line = String::new();
    let n = std::io::stdin().read_line(&mut line).ok()?;
    if n == 0 {
        return None; // EOF
    }
    let v = line.trim().to_string();
    Some(if v.is_empty() { default.to_string() } else { v })
}

fn interactive_menu() -> i32 {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    println!("asd2mp4 — Dual-Vision .asd converter");
    loop {
        println!("\nMain menu");
        println!("  1) Convert .asd files (H.264 MP4 + AAC audio)");
        println!("  2) Metadata only (no video)");
        println!("  3) Quit");
        let mut choice = String::new();
        if stdin.lock().read_line(&mut choice).unwrap_or(0) == 0 {
            return 0; // EOF
        }
        match choice.trim() {
            "3" | "q" | "Q" => return 0,
            "1" | "2" => {
                let metadata_only = choice.trim() == "2";
                let input = match prompt("Input (.asd file or folder)", ".") {
                    Some(v) => v,
                    None => return 0,
                };
                let outdir = match prompt("Output folder", "output") {
                    Some(v) => v,
                    None => return 0,
                };
                let channel_s = match prompt("Channel (enter=both, or 0 / 1)", "") {
                    Some(v) => v,
                    None => return 0,
                };
                let fps_s = match prompt("FPS (enter=auto)", "") {
                    Some(v) => v,
                    None => return 0,
                };
                let opts = Opts {
                    channel: channel_s.parse().ok(),
                    fps: fps_s.parse().ok(),
                    metadata_only,
                };
                let failed = run_batch(
                    std::path::Path::new(&input),
                    std::path::Path::new(&outdir),
                    &opts,
                );
                if failed == 0 {
                    println!("Done.");
                } else {
                    println!("Finished with {} failure(s).", failed);
                }
            }
            "" => continue,
            _ => println!("Please enter 1, 2 or 3."),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        std::process::exit(interactive_menu());
    }
    let input = PathBuf::from(&args[1]);
    let outdir = PathBuf::from(&args[2]);
    let mut opts = Opts::default();
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" => {
                i += 1;
                opts.channel = args.get(i).and_then(|v| v.parse().ok());
            }
            "--fps" => {
                i += 1;
                opts.fps = args.get(i).and_then(|v| v.parse().ok());
            }
            "--metadata-only" => opts.metadata_only = true,
            other => {
                eprintln!("unknown arg: {}", other);
                usage();
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let failed = run_batch(&input, &outdir, &opts);
    if failed > 0 {
        eprintln!("{} file(s) failed", failed);
        std::process::exit(1);
    }
}
