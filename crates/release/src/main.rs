//! `sync-release`: the release key and the signed manifest (docs/releasing.md).
//!
//! ```text
//! sync-release keygen <key file>
//! sync-release public <key file>
//! sync-release sign (--key <key file> | --key-env <VAR>) <file>
//! sync-release verify --public <public key> <file>
//! sync-release manifest --version <x.y.z> [--base-url <url>] --out <file> <binary>=<target>...
//! sync-release sums --out <file> <file>...
//! ```

use std::path::{Path, PathBuf};

use sync_release::minisign::SigningKey;
use sync_release::{Binary, manifest, sha256sums, verify};

const USAGE: &str = "usage:
  sync-release keygen <key file>
  sync-release public <key file>
  sync-release sign (--key <key file> | --key-env <VAR>) <file>
  sync-release verify --public <public key> <file>
  sync-release manifest --version <x.y.z> [--base-url <url>] --out <file> <binary>=<target>...
  sync-release sums --out <file> <file>...";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("sync-release: {e}");
        std::process::exit(1);
    }
}

/// Options as `(name, value)` and the other arguments, in order.
type Parsed = (Vec<(String, String)>, Vec<String>);

/// `--name value` pairs, then the rest in order.
fn options(args: &[String], names: &[&str]) -> Result<Parsed, String> {
    let mut opts = Vec::new();
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if !names.contains(&name) {
                return Err(format!("unknown option --{name}\n{USAGE}"));
            }
            let v = it.next().ok_or(format!("--{name} needs a value"))?;
            opts.push((name.to_string(), v.clone()));
        } else {
            rest.push(a.clone());
        }
    }
    Ok((opts, rest))
}

fn opt<'a>(opts: &'a [(String, String)], name: &str) -> Option<&'a str> {
    opts.iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// A new file only its owner can read; an existing one is never overwritten, so
/// a release key cannot be lost to a slip of the keyboard.
fn write_secret(path: &Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(text.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn run(args: &[String]) -> Result<(), String> {
    let Some((cmd, args)) = args.split_first() else {
        return Err(USAGE.into());
    };
    match cmd.as_str() {
        "keygen" => {
            let [file] = args else {
                return Err(USAGE.into());
            };
            let key = SigningKey::generate();
            write_secret(Path::new(file), &(key.export() + "\n"))?;
            println!("{}", key.public_base64());
            eprintln!(
                "Wrote the secret key to {file}. The line above is the public key: build the client with PITHAGORAS_SYNC_UPDATE_KEY set to it (docs/releasing.md)."
            );
        }
        "public" => {
            let [file] = args else {
                return Err(USAGE.into());
            };
            println!(
                "{}",
                SigningKey::import(&read(Path::new(file))?)?.public_base64()
            );
        }
        "sign" => {
            let (opts, rest) = options(args, &["key", "key-env"])?;
            let [file] = rest.as_slice() else {
                return Err(USAGE.into());
            };
            let text = match (opt(&opts, "key"), opt(&opts, "key-env")) {
                (Some(k), None) => read(Path::new(k))?,
                (None, Some(var)) => std::env::var(var)
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .ok_or(format!("{var} is not set"))?,
                _ => return Err(format!("sign needs --key or --key-env\n{USAGE}")),
            };
            let key = SigningKey::import(&text)?;
            let path = Path::new(file);
            let data = std::fs::read(path).map_err(|e| format!("{file}: {e}"))?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            write(
                Path::new(&format!("{file}.minisig")),
                &key.sign(&data, &format!("file:{name}")),
            )?;
        }
        "verify" => {
            let (opts, rest) = options(args, &["public"])?;
            let ([file], Some(public)) = (rest.as_slice(), opt(&opts, "public")) else {
                return Err(USAGE.into());
            };
            let data = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
            let sig = read(Path::new(&format!("{file}.minisig")))?;
            verify(&data, &sig, public)?;
            println!("{file}: the signature verifies");
        }
        "manifest" => {
            let (opts, rest) = options(args, &["version", "base-url", "out"])?;
            let (Some(version), Some(out)) = (opt(&opts, "version"), opt(&opts, "out")) else {
                return Err(USAGE.into());
            };
            let pairs: Vec<(PathBuf, String)> = rest
                .iter()
                .map(|a| match a.rsplit_once('=') {
                    Some((p, t)) => Ok((PathBuf::from(p), t.to_string())),
                    None => Err(format!("{a:?} is not <binary>=<target>")),
                })
                .collect::<Result<_, String>>()?;
            let binaries: Vec<Binary> = pairs
                .iter()
                .map(|(path, target)| Binary { path, target })
                .collect();
            write(
                Path::new(out),
                &manifest(version, opt(&opts, "base-url"), &binaries)?,
            )?;
        }
        "sums" => {
            let (opts, rest) = options(args, &["out"])?;
            let Some(out) = opt(&opts, "out") else {
                return Err(USAGE.into());
            };
            let files: Vec<&Path> = rest.iter().map(Path::new).collect();
            write(Path::new(out), &sha256sums(&files)?)?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
