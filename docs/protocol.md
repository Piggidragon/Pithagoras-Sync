# Pithagoras Sync wire protocol, version 1

What the device client (`pithagoras-sync`) and the portal say to each other. `crates/proto` is the code version of this page; change both together. The portal side is not written yet: this page is what it has to implement, and the client is tested against the mock portal in `crates/testkit`.

The device defends itself from the portal. Everything the portal sends is parsed strictly: unknown fields, unknown methods and malformed frames are errors, never ignored, so a field such as `env` on `exec.start` or `mode` on a file call cannot slip through.

## 1. Endpoints

The portal has a base URL: `https://host[:port][/prefix]`. `http://` is accepted only when every address the host resolves to is a loopback address (checked on the resolved addresses, not the name). The URL has no user info, query or fragment, and no `.` or `..` path segments.

| Endpoint | Use |
|---|---|
| `POST {base}/sync/v1/pair` | Trade a one-time code for a connector token (section 3). |
| `GET {base}/sync/v1/connect` | The WebSocket (section 4). |

### TLS

- With a pin (the `spki` from the pairing URI): the server certificate's SubjectPublicKeyInfo must hash (sha256) to the pin. Name, issuer and expiry are not checked, so a self-signed certificate works. The handshake signature is still verified against that key, so a server that only copied the certificate fails.
- Without a pin: the certificate is checked against the system's root store (`rustls-native-certs`), with the usual name and expiry checks.
- TLS 1.2 and 1.3, through rustls with the ring provider.

The pin is the base64url encoding, without padding, of sha256 over the DER SubjectPublicKeyInfo. For a PEM certificate:

```sh
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | basenc --base64url | tr -d '='
```

## 2. The pairing URI

The portal shows it as text and as a QR code:

```
pithagoras-sync://pair?portal=<pct-encoded base URL>&code=<code>[&spki=<pin>]
```

- `portal`: the base URL, percent-encoded.
- `code`: the one-time code, 1 to 64 ASCII letters and digits.
- `spki`: optional pin (section 1). Without it, the system's roots apply.
- A key given twice, an unknown key or a bad escape makes the URI invalid. A newer portal that adds keys has to bump this page; the client refuses rather than pair with half the meaning.

## 3. Pairing

```
POST {base}/sync/v1/pair
Content-Type: application/json

{"code": "<code>", "name": "<device name>", "os": "linux", "arch": "x86_64"}
```

- `name`: 1 to 24 of `a-z`, `0-9` and `-`; `server` and `portal` are reserved. By default the client derives it from the host name.
- `os`, `arch`: Rust's `std::env::consts` values (`linux`, `windows`; `x86_64`, `aarch64`).

Success is any 2xx with:

```json
{"device_id": "<1 to 128 chars>", "connector_token": "<16 to 512 printable ASCII>", "overlay_token": "<optional>"}
```

Unknown fields in this answer are ignored, since nothing in it can widen the device's policy. Phase 1 stores only `connector_token` (a 0600 file, `~/.config/pithagoras-sync/token` on Linux) and drops `overlay_token`, which belongs to the phase 2 GUI.

On a non-2xx answer the client shows the status and the body's `error` string (`{"error": "..."}`), or the first 200 characters of the body.

HTTP limits on the client: 16 KiB of headers, 1 MiB of body, 30 s for the whole exchange. The client sends `Connection: close`, and supports `Content-Length` or chunked answers.

## 4. Connecting

The client opens a WebSocket to `{base}/sync/v1/connect` (`wss://`, or `ws://` for loopback) with:

```
Authorization: Bearer <connector_token>
User-Agent: pithagoras-sync/<version>
```

What the portal's answer to the upgrade means to the client:

| Answer | Client |
|---|---|
| 101 | Connected; sends `hello` at once. |
| 401 | The token is unknown or revoked: the client stops connecting and asks for pairing again. It does not retry. |
| 409 | This device already has a live connection: the client retries with backoff. |
| anything else, or a network error | Retries with backoff. |

The client's limits: 15 s to open the TCP connection, 30 s for the WebSocket handshake, 4 MiB per message.

### Close codes

| Code | Sent by | Meaning | Client |
|---|---|---|---|
| 1000 | device | Paused on the device (`pithagoras-sync panic`). | Stays down until `pithagoras-sync unlock`. |
| 1001 | device | The client is shutting down. | |
| 4001 | portal | Device removed or token revoked. | Stops until paired again. |
| 4002 | portal | Another connection of this device took over. | Retries with backoff. |
| 4003 | portal | The portal does not speak this `proto` version. | Stops and asks for an update. |
| other | portal | | Retries with backoff. |

### Backoff, ping, dead connection

- The wait before the next attempt starts at 1 s and doubles to 60 s. Up to a tenth of each wait is subtracted at random, so devices do not reconnect in step after a portal restart. A connection that lasted 60 s resets the backoff to 1 s; so does an unlock.
- The client pings every 20 s. The portal answers with a pong (WebSocket control frame, which every WebSocket library does by itself).
- A connection on which nothing at all arrived for 45 s is dead; the client drops it and reconnects.

### No resume

When a connection ends for any reason, the device kills every command it runs (section 7) and forgets every upload in flight. Nothing is re-sent on the next connection. The portal fails its pending calls at once when the socket closes.

## 5. Text frames: JSON-RPC 2.0

Text frames carry one JSON-RPC 2.0 object each. No batches.

- Request (portal to device): `{"jsonrpc": "2.0", "id": <id>, "method": "...", "params": {...}}`.
- Notification (either way): the same without `id`.
- Response (device to portal): `{"jsonrpc": "2.0", "id": <id>, "result": ...}` or `{"jsonrpc": "2.0", "id": <id>, "error": {"code": <int>, "message": "...", "data"?: ...}}`.
- `id` is an integer or a string. `null`, floats, objects and arrays are refused.
- `params` must be an object. For methods without params it is `{}` (or left out).
- A frame that is not valid JSON, or that has a top-level field other than `jsonrpc`, `id`, `method` and `params`, is answered with `PARSE_ERROR` and `"id": null`. That includes a response from the portal: the device never sends requests in phase 1, so the portal never answers one.
- A bad `id` is `INVALID_REQUEST` with `"id": null`. A `jsonrpc` other than `"2.0"` or a missing `method` is `INVALID_REQUEST` on the frame's `id` (or `null` for a notification); `params` that are not an object are `INVALID_PARAMS`.
- The portal picks the ids. It must not reuse an id while that call is still pending.

### Error codes

| Code | Name | When |
|---|---|---|
| -32700 | PARSE_ERROR | Not valid JSON, or an unknown top-level field. |
| -32600 | INVALID_REQUEST | A bad `id` or `jsonrpc`, no `method`. |
| -32601 | METHOD_NOT_FOUND | Unknown method. |
| -32602 | INVALID_PARAMS | Params that do not fit the method, unknown fields included. |
| -32603 | INTERNAL | A bug on the device. |
| -32001 | DENIED | The policy refused, or an approval was denied or timed out. `message` says why. |
| -32002 | NOT_FOUND | The path does not exist; `exec.signal` for a stream that is not running. |
| -32003 | CONFLICT | `fs.write`'s `if_match` no longer matches. |
| -32004 | TOO_LARGE | Over a size limit (section 9). |
| -32005 | IO | Any other I/O failure, an upload that stopped early. |
| -32006 | BUSY | A limit on calls, uploads or running commands is reached. Retry later. |
| -32007 | BAD_PATH | A path the device refuses to interpret (section 6). |

### Concurrency

The device handles up to 64 calls at once and answers more with `BUSY`. Answers come in whatever order calls finish, so the portal matches them by `id`. A call waiting for an approval holds its slot.

## 6. Paths and the call context

Every path is absolute and in one form on every platform: `/home/alice/x` on Linux, `/c/Users/alice/x` for `C:\Users\alice\x` on Windows. The portal translates drive letters. The device refuses (`BAD_PATH`) relative paths, untranslated `C:\` or `C:/` paths, UNC and `\\?\` paths, backslashes in a Windows path, NUL bytes, Windows device names (`CON`, `NUL`, `COM1`...) and components Windows would change or read as a stream (`:`, a trailing dot or space, `*` and `?`). It then resolves symlinks and `..` and judges the real path; the open checks again (`openat2` refusing every symlink on Linux, the handle's final path on Windows), so a symlink swapped in between fails the call.

Calls on behalf of a chat carry a context:

```json
"ctx": {"chat": "<chat id>", "tainted": false}
```

- `chat`: which chat the call is for. Approvals ("for this chat") and the device's own taint are kept per chat.
- `tainted`: the portal guard's taint flag for that chat. The device only ever adds it to its own taint; `false` cannot clear anything.
- Any other field in `ctx` is refused. There is no way to send "approved", a mode, folders or protections; those exist only on the device.

## 7. Methods, portal to device

Requests. `ctx` is as in section 6.

### `device.info`

Params: `{}`. Result:

```json
{
  "name": "laptop", "os": "linux", "arch": "x86_64",
  "os_release": "Zorin OS 18", "hostname": "laptop",
  "user": "alice", "uid": 1000, "home": "/home/alice",
  "shell": "bash",
  "session": "wayland",
  "mode": "ask", "mode_expires_ms": null,
  "folders": [{"path": "/home/alice/src", "access": "rw"}],
  "folders_shell": "landlock",
  "mcp_tools": [],
  "client_version": "0.1.0"
}
```

- `shell`: what the `bash` tool runs: `bash` or `sh` on Linux, `pwsh` or `powershell` on Windows, or the stem of the configured shell. The tool keeps its name; the model has to write for this shell.
- `session`: `headless`, `wayland`, `x11` or `windows`.
- `mode`: the mode in force now, `ask`, `folders` or `full` (after Full's expiry, the restricted default).
- `mode_expires_ms`: when Full ends (Unix ms); `null` when not Full or set to never.
- `folders_shell`: how the shell runs in Folders mode: `landlock`, `prompt` (every command asks; denied headless; also what `landlock` falls back to without kernel support) or `unconfined`.
- `mcp_tools`: always empty in phase 1.

### `device.probe`

The same-machine check: the portal writes a file into its temp directory and asks whether the device sees it.

Params: `{"path": "/tmp/pithagoras-probe-<32 lowercase hex>"}`. Result:

```json
{"found": true, "sha256": "<hex of the file's content>", "user": "alice", "uid": 1000}
```

The device answers `found: true` only for a regular file named `pithagoras-probe-<32 hex>` directly in one of its temp directories (`/tmp`, `/var/tmp`, `$TMPDIR`; `%TEMP%` on Windows), opened without following symlinks and at most 4 KiB. Any other name is `BAD_PATH`; any other folder answers `found: false`. So the probe cannot be used to learn about other paths. It needs no `ctx` and is not subject to the mode.

### `fs.stat`

Params: `{"path": "...", "ctx": {...}}`. Result:

```json
{"kind": "file", "size": 1234, "mtime_ms": 1760000000000, "mode": 420}
```

`kind` is `file`, `dir`, `symlink` or `other`; `mode` holds the permission bits (`0o644` is 420).

### `fs.list`

Params: `{"path": "...", "ctx": {...}}`. Result:

```json
{"entries": [{"name": "src", "kind": "dir"}], "truncated": false}
```

At most 20 000 entries; `truncated` says more were left out. Protected entries are listed by name (a name is not content).

### `fs.read`

Params: `{"path": "...", "stream": <u32>, "ctx": {...}}`.

The content comes first as binary `FileData` frames on `stream` (section 8), `seq` from 0, up to 64 KiB each, then the result:

```json
{"size": 1234, "sha256": "<hex>", "chunks": 1}
```

`chunks` is how many frames were sent; an empty file sends none. The portal chooses `stream`; it must be unique among its open reads. Files over 64 MiB are `TOO_LARGE`.

### `fs.write`

Params:

```json
{"path": "...", "stream": <u32>, "size": <bytes>, "if_match": "<hex>", "create_dirs": false, "ctx": {...}}
```

- The content follows the request as binary `FileUpload` frames on `stream`, in order, up to 64 KiB each, `size` bytes in all. `size: 0` writes an empty file and no frames follow.
- `if_match` (optional): the sha256 from an earlier `fs.read`. The write fails with `CONFLICT` if the file changed since. Left out, the write is unconditional.
- `create_dirs` (optional): create missing parent folders.

Result: `{"size": 1234, "sha256": "<hex>"}`.

Rules:

- The device collects the whole upload before it asks the policy, so an approval prompt can show the content and a slow answer never stalls the connection. The prompt shows the first 2000 characters of the new content (not a diff), or "binary content, N bytes".
- More data than `size` is `TOO_LARGE`. A gap of 60 s with no frame, or the connection ending first, is `IO`. Frames for a stream with no pending write are dropped.
- At most 4 uploads at once (`BUSY`), 64 MiB each (`TOO_LARGE`, checked against `size` before any frame is taken). A `stream` already in use by an upload is `INVALID_PARAMS`.
- The file is written in place (created or truncated), as pi's own write does; it is not replaced through a temp file. Ownership and permissions of an existing file stay.

### `fs.grep`

Params:

```json
{"path": "...", "pattern": "regex", "glob": "*.rs", "ignore_case": false, "literal": false, "context": 0, "limit": 100, "ctx": {...}}
```

All but `path`, `pattern` and `ctx` are optional. `path` is a file or a folder; `glob` matches paths relative to it. Results honour `.gitignore`. Result:

```json
{"lines": [{"path": "/abs/file", "line": 12, "text": "...", "context": false}], "truncated": false, "skipped": 0}
```

`limit` defaults to 100 match lines and is capped at 10 000; lines are cut at 2000 characters. `skipped` counts files left out because they are protected, outside the granted folders, or unreadable.

### `fs.find`

Params: `{"path": "...", "pattern": "**/*.rs", "limit": 1000, "ctx": {...}}`. Result:

```json
{"paths": ["/abs/a.rs"], "truncated": false, "skipped": 0}
```

`limit` defaults to 1000, capped at 10 000.

### `exec.start`

Params:

```json
{"stream": <u32>, "command": "cargo test", "cwd": "/abs/dir", "timeout_ms": 600000, "ctx": {...}}
```

- There is no `env`: the device runs commands in its own scrubbed login environment (`PATH`, `HOME`, `LANG` and a short list, plus what the owner passes through; never `PORTAL_*`). An `env` field is refused as unknown.
- `timeout_ms` (optional) is capped by the device (4 hours by default).
- The answer is `{}` once the command started (or an error, and nothing else follows). Then come `ExecOutput` frames on `stream` (stdout and stderr merged, `seq` from 0), and last the `exec.exit` notification (section 9).
- Output beyond the device's cap (16 MiB by default) is dropped; `exec.exit` says `truncated`. Output of background processes after the shell's exit is not forwarded.
- Each command runs in its own process scope. On Linux a small shim between client and shell is a child subreaper, so everything the command starts stays below it; when the client runs in a systemd unit with `Delegate=yes` the command also gets its own cgroup. On Windows the scope is a Job Object. Timeout, `exec.signal`, pause and the end of the connection kill the whole scope, `setsid` and `nohup` children included.
- At most 16 commands at once by default (`BUSY`); a `stream` already running is `INVALID_PARAMS`.

### `exec.signal`

Params: `{"stream": <u32>, "signal": "SIGINT" | "SIGTERM" | "SIGKILL"}`. Result: `{}`.

`SIGINT` goes to the shell's process group (a Ctrl-C); `SIGTERM` reaches the whole scope, followed by `SIGKILL` after 3 s; `SIGKILL` kills it at once. On Windows every signal ends the Job Object. Other signal names are `INVALID_PARAMS`; a stream that is not running is `NOT_FOUND`.

### Not in phase 1

`mcp.list` and `mcp.call` (computer use) are phase 2 and answered with `METHOD_NOT_FOUND`. `hello` does not announce them.

## 8. Binary frames

```
u8 kind | u32 stream | u32 seq | payload
```

Integers big-endian; the header is 9 bytes, the payload at most 64 KiB. A frame shorter than the header, with a longer payload or with an unknown kind is dropped.

| kind | Name | Direction | Carries |
|---|---|---|---|
| 1 | ExecOutput | device to portal | Output of `exec.start` on `stream`. |
| 2 | FileData | device to portal | Content of `fs.read`, before its result. |
| 3 | FileUpload | portal to device | Content of `fs.write`, after its request. |

`seq` counts from 0 per stream. Frames of one stream arrive in order (one WebSocket), so `seq` is there for checking, not reordering.

Backpressure: the device has a send queue of 64 frames. When the portal reads slowly, file reads and command output wait instead of piling up in memory.

## 9. Notifications

### Device to portal

`hello`, the first frame on every connection:

```json
{"proto": 1, "device_id": "<id>", "client_version": "0.1.0", "os": "linux", "user": "alice", "shell": "bash", "capabilities": ["fs", "grep", "find", "exec", "probe"]}
```

There is no answer to `hello`. A portal that does not speak `proto` closes with 4003.

`exec.exit`, after the last `ExecOutput` frame of a stream:

```json
{"stream": 7, "code": 0, "signal": null, "timed_out": false, "truncated": false}
```

`code` is set when the shell exited, `signal` (`SIGKILL`, `SIGTERM`...) when it was killed.

`audit`: one decision for the portal's Audit page. Only decisions are mirrored (denials, approvals, mode changes, pauses), never every call:

```json
{"time_ms": 1760000000000, "chat": "<id or null>", "tool": "write", "target": "/abs/path", "decision": "denied", "reason": "protected path"}
```

`approval.waiting`: a call waits for the owner's answer on the device, so the portal can show "waiting for approval on <device>":

```json
{"id": <the call's id>, "chat": "<chat id>"}
```

The call's response follows when the owner answers, or `DENIED` when the approval times out (120 s by default).

### Portal to device

`grant.end`: a chat's grant of this device ended. The device clears that chat's approvals and taint.

```json
{"chat": "<chat id>"}
```

Any other notification is ignored (logged at debug level); bad params on `grant.end` are logged and ignored, since there is no id to answer.

## 10. Limits

| What | Limit |
|---|---|
| WebSocket message | 4 MiB |
| Binary payload | 64 KiB |
| Calls at once | 64 |
| Uploads at once | 4 |
| Read or write size | 64 MiB |
| Upload stall | 60 s |
| Running commands | 16 (config `exec.max_running`) |
| Command timeout | 4 h (config `exec.max_timeout_secs`) |
| Command output | 16 MiB (config `exec.output_cap_bytes`) |
| `fs.list` entries | 20 000 |
| grep / find results | 100 / 1000 by default, 10 000 at most |
| Approval timeout | 120 s (config `policy.approval_timeout_secs`, 1 to 3600) |
| Ping / dead | 20 s / 45 s |
| Backoff | 1 s to 60 s |

## 11. Open points

What the architecture left open and how phase 1 decided it. Each can still change before the portal side is written.

1. **Close codes.** 4001 revoked (stop), 4002 replaced (retry), 4003 unsupported protocol (stop). The architecture only says "one live connection per device".
2. **409 on connect** means "another live connection" and is retried with backoff; the portal raises its alert. If the portal prefers to replace the old connection, it closes that one with 4002.
3. **401 on connect** stops the client until it is paired again (`pithagoras-sync pair`). It does not keep knocking with a dead token.
4. **No answer to `hello`.** The portal either accepts the connection silently or closes it (4003). A version handshake can be added with `proto: 2`.
5. **Pin semantics.** The pin covers the key only: certificate name and expiry are ignored when a pin is set. Renewing the certificate with the same key keeps working; a new key needs pairing again.
6. **The approval preview is the head of the new content, not a diff.** A diff needs the old content and a diff library; phase 1 shows the first 2000 characters. The architecture asks for a diff for writes into `.git/` and similar folders; that is a phase 1 gap.
7. **`unpair` does not tell the portal.** It deletes the local token and portal entry; the device stays listed in the portal until removed there. There is no revoke endpoint for the device to call.
8. **`mcp.list` and `mcp.call` are not in phase 1.** They answer `METHOD_NOT_FOUND`; `capabilities` will announce `mcp` when they exist.
9. **Folder access for the dedicated user** is granted with POSIX ACLs (`setfacl`); `setup --create-user` prints the commands instead of running them, since it cannot know the folders.
10. **New folder grants are read-only** unless the owner passes `--rw`.
11. **The control socket lives in the state folder** (`~/.local/state/pithagoras-sync/run/control.sock`), not in `$XDG_RUNTIME_DIR`: a system unit has no runtime dir, and the CLI in the same user's login shell has to find the same socket.
12. **Output after the shell exits is dropped.** Background processes a command leaves behind keep running until the scope is killed (timeout, signal, pause, disconnect) but their output is not forwarded.
13. **The updater is not built.** The architecture's signed manifest (minisign) needs a release channel and a key; neither exists yet.
14. **The portal's `tainted` flag** is only ever added to the device's own taint. Taint ends with `grant.end`, or when the client restarts (taint is not persisted; the portal's flag brings it back on the next call).
15. **"Let the portal approve" is not built.** The architecture keeps it as an opt-in per device; it needs a portal-to-device answer to `approval.waiting`, which this version does not define. Approvals happen on the device only.
16. **The root password for `sudo`** (asked in a device dialog, handed over through `SUDO_ASKPASS`) needs the phase 2 GUI. In phase 1, root works by running the client as root or through a sudoers rule the owner writes; pattern prompts still catch `sudo` outside Full mode's settings.
