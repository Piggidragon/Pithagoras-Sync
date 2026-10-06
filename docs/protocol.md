# Pithagoras Sync wire protocol, version 1

What the device client (`pithagoras-sync`) and the portal say to each other. `crates/proto` is the code version of this page; change both together. The portal side is not written yet: this page is what it has to implement, and the client is tested against the mock portal in `crates/testkit`.

The device defends itself from the portal. Everything the portal sends is parsed strictly: unknown fields, unknown methods and malformed frames are errors, never ignored, so a field such as `env` on `exec.start` or `mode` on a file call cannot slip through.

## 1. Endpoints

The portal has a base URL: `https://host[:port][/prefix]`. `http://` is accepted only when every address the host resolves to is a loopback address (checked on the resolved addresses, not the name). Loopback does not tell one local user from another, so for plain http a host name takes only its IPv4 loopback addresses (`localhost` resolves to `::1` first, and a portal that listens on IPv4 leaves `[::1]` on its port free for any local user), a literal address is used as written, and on Linux the client checks in `/proc/net/tcp` and `tcp6`, before it sends anything (the pairing code, the token), that the connection's server-side socket and every socket listening where the connection could have arrived belong to its own user or root, and that there is at least one such listener; otherwise it refuses. Those are the listeners in the table the connection's entry is in (an IPv6 listener's connections are listed in `tcp6`, an IPv4 one's in `tcp`): on the connection's address and port, on the wildcard `0.0.0.0` or `[::]` on that port, and for an IPv4 connection on an IPv6 socket also the v4-mapped address and the mapped wildcard `[::ffff:0.0.0.0]`. An entry in both tables is refused. The listeners count because Linux 6.16 and older list a connection that is not accepted yet with uid 0, which alone would let another user's program that holds off `accept` pass as root. An IPv4 connection is looked up in both tables, since a portal listening dual-stack on `[::]` accepts it on an IPv6 socket. A portal in another network namespace reached through NAT (a container whose port is forwarded without a proxy process, Docker's `userland-proxy: false`) is not in those tables, so plain http to it is refused: use https there. On Windows plain http trusts every local account. The URL has no user info, query or fragment, and no `.` or `..` path segments.

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
- When the owner stored an elevation password (section 7, `exec.start`), every text frame the device sends is scrubbed of it before it leaves: as it is and in its JSON-escaped form, replaced by `[redacted]`. So are the command output frames.

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
"ctx": {"chat": "<chat id>", "tainted": false, "tool": "edit"}
```

- `chat`: which chat the call is for, at most 256 bytes without control characters (else `INVALID_PARAMS`). Approvals ("for this chat") and the device's own taint are kept per chat, for at most 4096 chats: past that the chat unused longest is forgotten.
- `tainted`: the portal guard's taint flag for that chat. The device only ever adds it to its own taint; `false` cannot clear anything.
- `tool` (optional): the pi tool the call is for, `read`, `write`, `edit`, `bash`, `grep`, `find` or `ls`. The owner can switch each tool off (`policy.tools`, see permissions.md); a call for a tool that is off is `DENIED`. The label can only narrow: it has to fit the method (`fs.read` serves `read` and `edit`, `fs.write` serves `write` and `edit`, `fs.stat` serves every tool but `bash`, `fs.list` serves `ls`, `fs.grep` serves `grep`, `fs.find` serves `find`, `exec.start` serves `bash`), and another label is `DENIED`. Without it, a call passes when any tool its method serves is on.
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
  "folders": [{"path": "/home/alice/src", "access": "rw", "execute": true}],
  "folders_shell": "landlock",
  "tools": ["read", "write", "edit", "bash", "grep", "find", "ls"],
  "mcp_tools": [],
  "client_version": "0.1.0"
}
```

- `shell`: what the `bash` tool runs: `bash` or `sh` on Linux, `pwsh` or `powershell` on Windows, or the stem of the configured shell. The tool keeps its name; the model has to write for this shell.
- `session`: `headless`, `wayland`, `x11` or `windows`.
- `mode`: the mode in force now, `ask`, `folders` or `full` (after Full's expiry, the restricted default).
- `mode_expires_ms`: when Full ends (Unix ms); `null` when not Full or set to never.
- `folders[].execute`: commands may run in that folder in Folders mode (`folder add --exec`).
- `folders_shell`: how the shell runs in Folders mode: `landlock`, `prompt` (every command asks; also what `landlock` falls back to without kernel support) or `unconfined`.
- `tools`: the pi tools switched on. The portal offers the device to these tools only.
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

At most 20 000 entries, and at most about 3 MiB of answer (section 10); `truncated` says more were left out. Protected entries are listed by name (a name is not content).

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

`limit` defaults to 100 match lines and is capped at 10 000; lines are cut at 2000 characters. `pattern` and `glob` have at most 4096 bytes, and the compiled pattern and its search cache are limited to 8 MiB each; a pattern beyond that (`\w{2000}`, say) is `INVALID_PARAMS`. The answer stops at about 3 MiB, context lines counted, and then says `truncated`, so it always fits one message. `skipped` counts files left out because they are protected, outside the granted folders, or unreadable.

### `fs.find`

Params: `{"path": "...", "pattern": "**/*.rs", "limit": 1000, "ctx": {...}}`. Result:

```json
{"paths": ["/abs/a.rs"], "truncated": false, "skipped": 0}
```

`limit` defaults to 1000, capped at 10 000; the answer stops at about 3 MiB with `truncated`.

### `exec.start`

Params:

```json
{"stream": <u32>, "command": "cargo test", "cwd": "/abs/dir", "timeout_ms": 600000, "ctx": {...}}
```

- There is no `env`: the device runs commands in its own scrubbed login environment (`PATH`, `HOME`, `LANG` and a short list, plus what the owner passes through; never `PORTAL_*`). An `env` field is refused as unknown.
- `timeout_ms` (optional) is capped by the device (4 hours by default).
- `command` has at most 128 KiB (about the most Linux passes to a shell as one argument); a longer one is `TOO_LARGE` before the policy sees it.
- The answer is `{}` once the command started (or an error, and nothing else follows). Then come `ExecOutput` frames on `stream` (stdout and stderr merged, `seq` from 0), and last the `exec.exit` notification (section 9).
- Output beyond the device's cap (16 MiB by default) is dropped; `exec.exit` says `truncated`. Output of background processes after the shell's exit is not forwarded.
- Each command runs in its own process scope. On Linux a small shim between client and shell is a child subreaper, so everything the command starts stays below it; when the client runs in a systemd unit with `Delegate=yes` the command also gets its own cgroup. On Windows the scope is a Job Object, kept while processes are left in it. Timeout, `exec.signal`, pause and the end of the connection kill the whole scope, `setsid` and `nohup` children included. A process that another service starts for the command (`systemd-run --user`, a Windows scheduled task or WMI) is outside the scope.
- At most 16 commands at once by default (`BUSY`), commands still being started included; a `stream` already running or starting is `INVALID_PARAMS`.
- A pause (`panic`) or the end of the connection while a command is being started kills it before it enters the device's table of running commands, and the call answers `DENIED`. While the device is paused no command starts.
- The shim gets its instructions (program, working folder, environment) on its stdin, never in its command line, which every user of the machine can read.

Elevated commands (Linux only, and only when the owner set `policy.privilege.elevation = "sudo"`):

- A device whose client already runs as root (`geteuid() == 0`, an LXC for example) elevates nothing: its `sudo ...` is an ordinary command, and neither this rule nor the question below applies. Its `sudo`, `su`, `doas` and `pkexec` do not ask as command patterns either (Full mode, the unconfined Folders shell); the other patterns do.
- A command that starts with the word `sudo` runs as root: the device runs `sudo` itself and the shell under it with the rest of the command. `sudo` with options of its own (`sudo -u nobody ...`) or alone is `DENIED`; only `sudo <command>`, as root, is taken. With elevation off, `sudo` is an ordinary word of the command and runs as the user would type it.
- The password is the one the owner typed on the device (`pithagoras-sync sudo set`). The device hands it to `sudo -S` on a private channel; it never appears in the command line, the environment, the command's stdin (closed before the command starts) or anything sent to the portal. Without a stored password the device runs `sudo -n`, which works with a sudoers rule that asks none and fails otherwise.
- An elevated command always asks for approval, in every mode, unless it matches the owner's `policy.commands.never_ask` list. It needs a cgroup of its own (the systemd unit's `Delegate=yes`), so that `panic` can kill root's processes: where that cgroup cannot be made or joined, the command is `DENIED` or does not run. It is `DENIED` where the shell runs under Landlock (sudo cannot gain rights under `no_new_privs`): in Folders mode it needs `folders_shell = "unconfined"`.

### `exec.signal`

Params: `{"stream": <u32>, "signal": "SIGINT" | "SIGTERM" | "SIGKILL"}`. Result: `{}`.

`SIGINT` goes to the shell's process group (a Ctrl-C); `SIGTERM` reaches the whole scope, followed by `SIGKILL` after 3 s; `SIGKILL` kills it at once. On Windows every signal ends the Job Object. Other signal names are `INVALID_PARAMS`; a stream that is not running is `NOT_FOUND`.

### `approval.answer`

The owner's answer to an approval the device asked for (`approval.requested`, section 9), from the portal's Devices tab. Only when `hello` announced `approvals`; otherwise `METHOD_NOT_FOUND`.

Params:

```json
{"id": 12, "answer": "time", "minutes": 30}
```

- `id`: the approval's id from `approval.requested`.
- `answer`: one of the request's `choices`:
  - `once`: this call only.
  - `chat`: this call and further calls of the same kind (reads or writes) from the same chat, until the chat's grant ends or `policy.approvals.remember_minutes` run out.
  - `time`: the same for `minutes`, from 1 to the request's `max_minutes`.
  - `deny`: refuse it; the waiting call answers `DENIED`.
- `minutes`: only with `time`.

`chat` and `time` are offered only in Ask mode, for a read or a write, where a whole kind of call asks. A command offers only `once` and `deny` in every mode (a standing approval of the shell would cover any command), and so does a question raised by a protected path, a pattern, taint or an elevated command.

Result: `{}`. An approval that is not waiting (answered, timed out, withdrawn, unknown) is `NOT_FOUND`; an answer not in `choices`, or wrong `minutes`, is `INVALID_PARAMS`. The first answer wins, from wherever it comes (the portal, the local `approve` and `deny`, a desktop notification); the waiting call's response follows.

### `approval.list`

The approvals waiting now, for a Devices tab opened after they were asked. Approvals belong to the calls of the current connection: when it ends, the calls end and their approvals are withdrawn (`approval.resolved` with `by: "withdrawn"` goes nowhere then, so the portal drops them itself). Only with `approvals` in `hello`. Params: `{}`. Result: `{"approvals": [<ApprovalInfo>...], "left_out": 2}`, each as in `approval.requested`. The answer holds at most about 3 MiB of JSON; approvals past that are left out and counted in `left_out` (absent when none are), and come in as the ones before them are answered.

### `policy.get`

The device's settings, for the portal's Devices tab. `hello` announces `policy` when the owner's `portal_policy` is `read` or `write`; with `off` the call is `DENIED` (a device without settings to share, such as a test device, answers `METHOD_NOT_FOUND`). Params: `{}`. Result, a PolicyDocument:

```json
{
  "portal_policy": "read",
  "version": "9c1f0a2b3d4e5f60",
  "settings": {"policy": {...}, "exec": {...}},
  "device_only": ["exec.shell", "policy.privilege.sudo_path", "policy.privilege.secret_storage"]
}
```

- `settings`: the config file's `[policy]` and `[exec]` tables, every setting with its value, in the form of docs/permissions.md. Never in it: the pairing, the profile, `portal_policy` and the elevation password.
- `version`: a hash of `settings`; it changes whenever they do.
- `device_only`: settings in the document that only the device changes.

### `policy.set`

Replaces the settings. Only with `portal_policy = "write"`, which only the owner sets, on the device.

Params:

```json
{"settings": {"policy": {...}, "exec": {...}}, "if_version": "9c1f0a2b3d4e5f60"}
```

- `settings`: the whole document as `policy.get` returned it, changed. Every setting is checked as in the config file; an unknown field or a bad value is `INVALID_PARAMS`. So is a new folder whose path holds a control character, which would redraw the owner's terminal in `folder list`.
- `if_version` (optional): the `version` the change is based on. When the settings changed on the device meanwhile, the answer is `CONFLICT` and nothing changes. Left out, the change replaces whatever is there.
- With `portal_policy` `read` or `off`, `DENIED`. A change to a `device_only` setting is `DENIED` as a whole.
- The device keeps Full mode's end time itself: switching to Full dates it from now (`policy.full.until_ms` in the document is ignored).

Result: the new PolicyDocument. The device saves the config file, applies it at once and audits each changed setting with its old and new value (`"by the portal: true -> false"`); `policy.changed` follows.

A portal with write access can widen everything the document holds, Full mode included. That is the owner's choice when they set `write`; the default is `read`.

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
{"proto": 1, "device_id": "<id>", "client_version": "0.1.0", "os": "linux", "user": "alice", "shell": "bash", "capabilities": ["fs", "grep", "find", "exec", "probe", "approvals", "policy"]}
```

There is no answer to `hello`. A portal that does not speak `proto` closes with 4003.

`capabilities` always holds `fs`, `grep`, `find`, `exec` and `probe`. `approvals`: the device asks the portal for approvals (`approval.requested`) and takes answers (`approval.answer`, `approval.list`); the client always announces it. `policy`: the device shares its settings (`policy.get`, `policy.changed`, and `policy.set` when `portal_policy` is `write`); absent when the owner set `portal_policy = "off"`.

`exec.exit`, after the last `ExecOutput` frame of a stream:

```json
{"stream": 7, "code": 0, "signal": null, "timed_out": false, "truncated": false}
```

`code` is set when the shell exited, `signal` (`SIGKILL`, `SIGTERM`...) when it was killed.

`audit`: one decision for the portal's Audit page. Only decisions are mirrored (denials, approvals, mode changes, pauses), never every call:

```json
{"time_ms": 1760000000000, "chat": "<id or null>", "tool": "write", "target": "/abs/path", "decision": "denied", "reason": "protected path"}
```

A command's event also has `cwd`, the folder it runs in (as the portal gave it when it was refused before the device resolved it).

A settings change is one event per setting: `"tool": "policy"`, the setting's name in `target` (`policy.tools.bash`), `"decision": "changed"` and the old and new value in `reason` (`by the portal: true -> false`, `by the device owner: ...`).

`approval.requested`: a call waits for the owner's approval. The portal shows it in the Devices tab (and next to the chat) with the choices it offers, and sends the owner's answer with `approval.answer`. The owner can also answer on the device (`pithagoras-sync approvals`, `approve <id>`, `deny <id>`).

```json
{
  "id": 12, "call": 41, "chat": "<chat id>",
  "tool": "write", "target": "/home/alice/src/app/main.rs", "cwd": null,
  "reasons": ["Ask mode: every call asks"],
  "preview": "fn main() {...",
  "choices": ["once", "chat", "time", "deny"], "max_minutes": 480,
  "created_ms": 1760000000000, "expires_ms": 1760000120000
}
```

- `id`: the device's number for this approval; answers name it.
- `call`: the JSON-RPC id of the waiting call (`null` for a question that did not come from a portal call).
- `tool`, `target`: the method's tool (`read`, `write`, `ls`, `exec`, ...) and the path or command, with the elevation password scrubbed out.
- `cwd`: for a command, the folder it runs in, resolved as the device would run it (the same command means something else in another folder); absent for file calls.
- `reasons`: why it asks (the mode, a protected path, a command pattern, taint, an always-ask rule, an elevated command).
- `preview`: for a write, the first 2000 characters of the new content, or "binary content, N bytes".
- `choices`: the answers the device takes for this call (section 7, `approval.answer`). `max_minutes`: the longest `time` answer.
- `cut`: present and `true` when the command or path (or the folder) is longer than 64 KiB. They are then shown cut at 64 KiB, ending in `…`, and `choices` is only `deny`: nobody could read whole what they would allow. Each reason is cut at 4 KiB.
- `expires_ms`: when the device stops waiting. Nobody answering by then is a denial (`DENIED`, "no answer to the approval within 120s"), unless the owner set `policy.approvals.on_timeout = "allow"`.

`approval.resolved`: an approval ended, however it ended, so every view of it can close.

```json
{"id": 12, "chat": "<chat id>", "answer": "once", "minutes": null, "by": "portal"}
```

`by` is `portal` (an `approval.answer`), `device` (the local CLI), `notification` (a desktop notification), `timeout`, `pause` (`panic` denied it) or `withdrawn` (the call ended first, for instance because the portal's chat stopped it). `answer` is what the call got: `deny` for `pause` and `withdrawn`, and for `timeout` `deny` or, with `on_timeout = "allow"`, `once`.

`policy.changed`: the device's settings changed, by the owner on the device or through `policy.set`. Params: the new PolicyDocument (section 7, `policy.get`). Sent only while `portal_policy` is `read` or `write`.

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
| Uploads at once | 4 (each holds its slot until the write is done, its approval included; more are `BUSY`) |
| `fs.read` holding a file at once | 4 (more wait) |
| `fs.grep` and `fs.find` running at once | 4 (more wait) |
| grep pattern, grep or find glob | 4096 bytes; compiled pattern and search cache 8 MiB each |
| Read or write size | 64 MiB |
| `exec.start` command | 128 KiB |
| Upload stall | 60 s |
| Running commands | 16 (config `exec.max_running`) |
| Command timeout | 4 h (config `exec.max_timeout_secs`) |
| Command output | 16 MiB (config `exec.output_cap_bytes`) |
| `fs.list` entries | 20 000 |
| grep / find results | 100 / 1000 by default, 10 000 at most |
| One `fs.list`, `fs.grep` or `fs.find` answer | about 3 MiB of JSON, context lines included; past it the answer stops with `truncated: true` |
| Chat id (`ctx.chat`, `grant.end`) | 256 bytes, no control characters (else `INVALID_PARAMS`); the device keeps state for 4096 chats, forgetting the one unused longest |
| Audit record | target and reason cut at 4 KiB, chat id at 256 bytes |
| Approval text | command or path and folder 64 KiB (longer: cut, deny only), each reason 4 KiB; `approval.list` about 3 MiB, the rest counted in `left_out` |
| Approval timeout | 120 s (config `policy.approvals.timeout_secs`, 1 to 3600) |
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
10. **New folder grants are read-only, and run no commands,** unless the owner passes `--rw` and `--exec`.
11. **The control socket lives in the state folder** (`~/.local/state/pithagoras-sync/run/control.sock`), not in `$XDG_RUNTIME_DIR`: a system unit has no runtime dir, and the CLI in the same user's login shell has to find the same socket.
12. **Output after the shell exits is dropped.** Background processes a command leaves behind keep running until the scope is killed (timeout, signal, pause, disconnect) but their output is not forwarded.
13. **Updates come from a signed manifest** (`pithagoras-sync update`): `manifest.json` names the version, when it was released (Unix seconds) and per target the binary's URL, size and sha256, and `manifest.json.minisig` signs it with the release key compiled into the build (`PITHAGORAS_SYNC_UPDATE_KEY`). Only a newer version is taken, and a manifest released before the newest one the client took is refused (an older signed manifest served again); manifests do not expire, so `update --check` shows the release date; the new binary must report that version before it replaces the old one in one rename, and the client restarts through its unit. An update never touches the config or the policy. The manifest comes from the stable release channel, the newest GitHub release of the client's repository (`releases/latest/download/manifest.json`, docs/releasing.md), unless a build names another (`PITHAGORAS_SYNC_UPDATE_URL`) or the owner passes `--manifest`. A build without a key cannot update itself. The client does not check for updates on its own.
14. **The portal's `tainted` flag** is only ever added to the device's own taint. Taint ends with `grant.end`, or when the client restarts (taint is not persisted; the portal's flag brings it back on the next call).
15. **Approvals go through the portal** (`approval.requested`, `approval.answer`), and through the local CLI, on every device and every platform. A portal that answers approvals can allow what Ask mode asks for, so a compromised portal on an Ask device is as strong as Full mode: it can allow every question, protected paths included. There is no switch yet that keeps approvals on the device only; it can come with the phase 2 window. Desktop notifications with Allow and Deny are in the code but off by default (`policy.approvals.desktop_notifications`); the device's own approval window comes back with the phase 2 GUI.
16. **The root password for `sudo`** is typed on the device only (`pithagoras-sync sudo set`, a terminal prompt without echo, never an argument) and kept in the client's memory, or in a 0600 file when the owner chooses `secret_storage = "file"`. The OS keyring is not used: unlocked, it gives the password to every process of the user, as the file does, and a server has none. sudo gets it on stdin through the exec shim, which takes it from a private file descriptor only when nothing traces it. It is scrubbed from command output, every text frame, the audit log and the client's log. Not caught: base64 or other re-encodings a command prints, and the content of a file `fs.read` sends (binary frames are not scrubbed; the stored secret file itself is sealed, see 19). Elevation is Linux only: Windows has none, and none is planned.
17. **Root's commands always ask.** An elevated command asks for approval in every mode, Full included, unless the owner put it on the never-ask list. A client that runs as root has nothing to elevate: `sudo` and its kin change nothing for it, so they neither ask nor elevate there (owner's decision, 2026-10-06), while `git push`, `rm -r` outside the working folder and the other patterns still ask.
18. **What the portal can change** is the owner's choice, `portal_policy = off | read | write`, set on the device only (default `read`). `exec.shell`, `policy.privilege.sudo_path` and `policy.privilege.secret_storage` are device-only even with `write`: a portal that could change them could make the device hand the password to a program of its choosing.
19. **The secret file is sealed off.** The file tools refuse it in every mode, grep and find skip it, and Landlock leaves it out; an unconfined command (Full mode, or `folders_shell = "unconfined"`) of the same user can still read it, and only the output scrubbing stands between it and the portal. That is why memory is the default.
20. **Legacy minisign signatures are accepted** besides prehashed ones: the manifest is small, and Ed25519 over the whole of it is as strong.
