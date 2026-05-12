use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command as ProcessCommand};
use veilpaste_core::{restore, scrub, MappingStore, ScrubOptions};

#[derive(Debug, Parser)]
#[command(name = "veilpaste")]
#[command(version)]
#[command(about = "Local secret redaction before pasting developer context into AI")]
struct Cli {
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scrub {
        input: Option<PathBuf>,
        #[arg(long)]
        map: Option<PathBuf>,
        #[arg(long)]
        preview: bool,
        #[arg(long)]
        strict: bool,
    },
    Restore {
        input: PathBuf,
        #[arg(long)]
        map: PathBuf,
    },
    Check {
        input: PathBuf,
    },
    Explain {
        input: PathBuf,
    },
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(error) => {
            eprintln!("veilpaste: {error:#}");
            process::exit(2);
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    let quiet = cli.quiet;
    match cli.command {
        None => {
            let input = read_stdin()?;
            let result = scrub(&input, ScrubOptions::default())?;
            write_stdout(&result.output);
            Ok(0)
        }
        Some(Command::Scrub {
            input,
            map,
            preview,
            strict,
        }) => {
            let input_text = read_input(input.as_ref())?;
            let result = scrub(&input_text, ScrubOptions { preview, strict })?;
            if let Some(map_path) = map {
                warn_if_mapping_is_not_ignored(&map_path, quiet);
                if let Some(parent) = map_path.parent() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create mapping directory {}", parent.display())
                    })?;
                }
                let json = serde_json::to_string_pretty(&result.mapping_store())?;
                fs::write(&map_path, json).with_context(|| {
                    format!("failed to write mapping file {}", map_path.display())
                })?;
            }
            write_stdout(&result.output);
            Ok(0)
        }
        Some(Command::Restore { input, map }) => {
            let input_text = read_input(Some(&input))?;
            let map_text = fs::read_to_string(&map)
                .with_context(|| format!("failed to read mapping file {}", map.display()))?;
            let mapping: MappingStore = serde_json::from_str(&map_text)
                .with_context(|| format!("failed to parse mapping file {}", map.display()))?;
            let output = restore(&input_text, &mapping)?;
            write_stdout(&output);
            Ok(0)
        }
        Some(Command::Check { input }) => {
            let input_text = read_input(Some(&input))?;
            let result = scrub(&input_text, ScrubOptions::default())?;
            if result.findings.is_empty() {
                println!("No high-confidence secrets found.");
                Ok(0)
            } else {
                println!(
                    "{} high-confidence secret{} found:",
                    result.findings.len(),
                    if result.findings.len() == 1 { "" } else { "s" }
                );
                for finding in result.findings {
                    println!(
                        "- {:?} bytes {}..{} ({:?})",
                        finding.kind, finding.span.start, finding.span.end, finding.source
                    );
                }
                Ok(1)
            }
        }
        Some(Command::Explain { input }) => {
            let input_text = read_input(Some(&input))?;
            let result = scrub(&input_text, ScrubOptions::default())?;
            for finding in result.findings {
                println!(
                    "{:?}  {:?}  bytes {}..{}  {:?}",
                    finding.confidence,
                    finding.kind,
                    finding.span.start,
                    finding.span.end,
                    finding.source
                );
            }
            Ok(0)
        }
    }
}

fn read_input(path: Option<&PathBuf>) -> Result<String> {
    match path {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read input file {}", path.display())),
        None => read_stdin(),
    }
}

fn read_stdin() -> Result<String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read stdin")?;
    Ok(input)
}

fn write_stdout(output: impl AsRef<str>) {
    let _ = io::stdout().write_all(output.as_ref().as_bytes());
}

fn warn_if_mapping_is_not_ignored(map_path: &Path, quiet: bool) {
    if quiet || !is_inside_git_repo() || is_ignored_by_git(map_path) {
        return;
    }

    eprintln!(
        "WARNING: mapping file contains original secrets. Do not commit it. Add .veilpaste/ to .gitignore."
    );
}

fn is_inside_git_repo() -> bool {
    ProcessCommand::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn is_ignored_by_git(path: &Path) -> bool {
    ProcessCommand::new("git")
        .arg("check-ignore")
        .arg(path)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
