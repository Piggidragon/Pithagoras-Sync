//! The mock portal as a program, for trying a real client by hand (docs/testing.md).
//! It listens on loopback and reads one command per line from stdin, so a script
//! can drive it:
//!
//! ```text
//! code <CODE>                 accept a pairing code, print the pairing URI
//! wait [secs]                 wait for the next device to connect, print its hello
//! exec <cwd> <command...>     run a command, answering approvals per `approve`
//! approve once|deny|none      how `exec` answers approvals (default: none)
//! call <method> <json>        call any method on the device
//! mcp-list                    computer use: the device's servers and tools
//! mcp-call <server> <tool> [json]  call one, answering approvals per `approve`
//! read <path>                 fs.read, print the content
//! close                       close the link (the device reconnects)
//! closed [secs]               wait until the device's link ended, print the code
//! sleep <secs>
//! grep <text>                 whether anything the devices sent contains <text>
//! dump <file>                 write everything the devices sent to <file>
//! quit
//! ```

use std::io::BufRead;
use std::time::Duration;

use serde_json::{Value, json};
use sync_testkit::{DeviceLink, MockOptions, MockPortal};

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let mock = MockPortal::start_on(MockOptions::default(), port).await;
    println!("portal {}", mock.url);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut dl: Option<DeviceLink> = None;
    let mut stream = 0u32;
    let mut approve = "none".to_string();
    while let Some(line) = rx.recv().await {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        println!("> {line}");
        let (cmd, rest) = line.split_once(' ').unwrap_or((line, ""));
        let secs = |d: u64| Duration::from_secs(rest.trim().parse().unwrap_or(d));
        match cmd {
            "code" => {
                mock.add_code(rest.trim());
                println!("uri {}", mock.pair_uri(rest.trim()));
            }
            "wait" => match mock.next_device(secs(30)).await {
                Some(d) => {
                    println!("hello {}", d.hello);
                    dl = Some(d);
                }
                None => println!("no device connected"),
            },
            "approve" => approve = rest.trim().to_string(),
            "exec" => {
                let Some(d) = &dl else {
                    println!("no device");
                    continue;
                };
                let (cwd, command) = rest.split_once(' ').unwrap_or((rest, ""));
                stream += 1;
                exec(d, stream, cwd, command, &approve).await;
            }
            "call" => {
                let Some(d) = &dl else {
                    println!("no device");
                    continue;
                };
                let (method, params) = rest.split_once(' ').unwrap_or((rest, "{}"));
                let params: Value = serde_json::from_str(params).unwrap_or(json!({}));
                println!("{:?}", d.call(method, params).await);
            }
            "mcp-list" => match &dl {
                Some(d) => match d.mcp_list().await {
                    Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
                    Err(e) => println!("error {} {}", e.code, e.message),
                },
                None => println!("no device"),
            },
            "mcp-call" => {
                let Some(d) = &dl else {
                    println!("no device");
                    continue;
                };
                let mut parts = rest.splitn(3, ' ');
                let (server, tool) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                let args: Value =
                    serde_json::from_str(parts.next().unwrap_or("{}")).unwrap_or(json!({}));
                mcp_call(d, server, tool, args, &approve).await;
            }
            "read" => {
                let Some(d) = &dl else {
                    println!("no device");
                    continue;
                };
                stream += 1;
                let r = d
                    .call(
                        "fs.read",
                        json!({"path": rest.trim(), "stream": stream, "ctx": {"chat": "manual"}}),
                    )
                    .await;
                match r {
                    Ok(_) => println!("{}", String::from_utf8_lossy(&d.stream_data(stream))),
                    Err(e) => println!("error {e:?}"),
                }
            }
            "close" => {
                if let Some(d) = &dl {
                    d.close(1000, "closed by the mock portal").await;
                }
            }
            "closed" => match &dl {
                Some(d) => println!("closed {:?}", d.closed(secs(30)).await),
                None => println!("no device"),
            },
            "sleep" => tokio::time::sleep(secs(1)).await,
            "grep" => {
                let t = mock.transcript();
                let n = rest.as_bytes();
                let found = !n.is_empty() && t.windows(n.len()).any(|w| w == n);
                println!("grep {}", if found { "FOUND" } else { "absent" });
            }
            "dump" => match std::fs::write(rest.trim(), mock.transcript()) {
                Ok(()) => println!("dumped"),
                Err(e) => println!("error {e}"),
            },
            "quit" => break,
            other => println!("unknown command {other}"),
        }
    }
}

async fn exec(d: &DeviceLink, stream: u32, cwd: &str, command: &str, approve: &str) {
    let pending = d
        .start_call(
            "exec.start",
            json!({"stream": stream, "command": command, "cwd": cwd, "ctx": {"chat": "manual"}}),
        )
        .await;
    tokio::pin!(pending);
    let started = loop {
        tokio::select! {
            r = &mut pending => break r.unwrap_or(Err(sync_proto::RpcError::new(0, "closed"))),
            Some(a) = d.notification("approval.requested", Duration::from_secs(600)) => {
                println!("approval {} {:?}: {}", a["id"], a["reasons"], a["target"]);
                if approve != "none" {
                    let r = d.call("approval.answer", json!({"id": a["id"], "answer": approve})).await;
                    println!("answered {approve}: {r:?}");
                }
            }
        }
    };
    if let Err(e) = started {
        println!("refused {} {}", e.code, e.message);
        return;
    }
    match d.notification("exec.exit", Duration::from_secs(600)).await {
        Some(exit) => {
            print!("{}", String::from_utf8_lossy(&d.stream_data(stream)));
            println!("exit {exit}");
        }
        None => println!("no exit"),
    }
}

async fn mcp_call(d: &DeviceLink, server: &str, tool: &str, args: Value, approve: &str) {
    let pending = d
        .start_call(
            "mcp.call",
            json!({"server": server, "tool": tool, "args": args, "ctx": {"chat": "manual"}}),
        )
        .await;
    tokio::pin!(pending);
    let r = loop {
        tokio::select! {
            r = &mut pending => break r.unwrap_or(Err(sync_proto::RpcError::new(0, "closed"))),
            Some(a) = d.notification("approval.requested", Duration::from_secs(600)) => {
                println!("approval {} {:?}: {}", a["id"], a["reasons"], a["target"]);
                if approve != "none" {
                    let r = d.call("approval.answer", json!({"id": a["id"], "answer": approve})).await;
                    println!("answered {approve}: {r:?}");
                }
            }
        }
    };
    match r {
        Ok(v) => {
            // Images by their size: the data is long and of no use here.
            for c in v["content"].as_array().into_iter().flatten() {
                match c["type"].as_str() {
                    Some("image") => println!(
                        "image {} ({} bytes of base64)",
                        c["mime"],
                        c["data"].as_str().map_or(0, str::len)
                    ),
                    _ => println!("text {}", c["text"]),
                }
            }
            println!("is_error {}", v["is_error"]);
        }
        Err(e) => println!("refused {} {} {:?}", e.code, e.message, e.data),
    }
}
