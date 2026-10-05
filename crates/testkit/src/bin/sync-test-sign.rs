//! Test keys and signatures for trying the updater by hand (docs/testing.md):
//!
//! `sync-test-sign keygen <keyfile>` writes a key and prints its public key (the
//! value to build the client with as `PITHAGORAS_SYNC_UPDATE_KEY`);
//! `sync-test-sign sign <keyfile> <file>` writes `<file>.minisig`.

use sync_testkit::minisign::TestKey;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("keygen") if args.len() == 3 => {
            let k = TestKey::generate();
            std::fs::write(&args[2], k.export())
                .map_err(|e| e.to_string())
                .map(|()| {
                    println!("{}", k.public_base64());
                })
        }
        Some("sign") if args.len() == 4 => (|| {
            let k =
                TestKey::import(&std::fs::read_to_string(&args[2]).map_err(|e| e.to_string())?)?;
            let data = std::fs::read(&args[3]).map_err(|e| e.to_string())?;
            let name = std::path::Path::new(&args[3])
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            std::fs::write(
                format!("{}.minisig", args[3]),
                k.sign(&data, &format!("file:{name}")),
            )
            .map_err(|e| e.to_string())
        })(),
        _ => Err("usage: sync-test-sign keygen <keyfile> | sign <keyfile> <file>".into()),
    };
    if let Err(e) = r {
        eprintln!("sync-test-sign: {e}");
        std::process::exit(1);
    }
}
