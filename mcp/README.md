# Computer-use pins

`servers.json` is the input of `sync-release mcp`: the computer-use servers, their exact versions, download URLs and allowed tools. `mcp.json` and `mcp.json.minisig`, the signed pins document clients fetch from here, are made from it by the owner (docs/mcp-updates.md). Until then the clients use the pins built into them (`crates/mcp/pins/baseline.json`). Values still marked `TODO-PIN` have to be filled in from the upstream releases first.
