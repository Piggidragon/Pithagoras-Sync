//! A plain HTTP server on loopback that serves files from memory, for the
//! download tests: whole answers, redirects, and answers cut short.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone)]
pub enum Reply {
    /// 200 with the body.
    Body(Vec<u8>),
    /// A redirect to this URL.
    Redirect(String),
    /// 200 announcing `len` bytes but sending only the body, then closing.
    Short {
        body: Vec<u8>,
        len: usize,
    },
    Status(u16),
}

pub struct FileServer {
    /// `http://127.0.0.1:<port>`
    pub url: String,
    files: Arc<Mutex<HashMap<String, Reply>>>,
    /// The paths asked for, in order.
    pub asked: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FileServer {
    pub async fn start() -> FileServer {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let files: Arc<Mutex<HashMap<String, Reply>>> = Arc::default();
        let asked: Arc<Mutex<Vec<String>>> = Arc::default();
        let (f, a) = (files.clone(), asked.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let (f, a) = (f.clone(), a.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf);
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    a.lock().unwrap().push(path.clone());
                    let reply = f
                        .lock()
                        .unwrap()
                        .get(&path)
                        .cloned()
                        .unwrap_or(Reply::Status(404));
                    let out = match reply {
                        Reply::Body(b) => [format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).into_bytes(), b].concat(),
                        Reply::Redirect(to) => format!("HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes(),
                        Reply::Short { body, len } => [format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n").into_bytes(), body].concat(),
                        Reply::Status(c) => format!("HTTP/1.1 {c} No\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes(),
                    };
                    let _ = s.write_all(&out).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        FileServer {
            url,
            files,
            asked,
            task,
        }
    }

    /// Serves `reply` at `path` (`/srv`); returns its URL.
    pub fn put(&self, path: &str, reply: Reply) -> String {
        self.files.lock().unwrap().insert(path.to_string(), reply);
        format!("{}{path}", self.url)
    }
}

impl Drop for FileServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
