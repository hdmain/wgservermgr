# wireguard-go (with Management API)

Userspace [WireGuard](https://www.wireguard.com/) implementation in Go, extended with a built-in HTTP management API for creating users (peers), issuing client configs, and applying per-user bandwidth limits on Linux.

This project is based on [wireguard-go](https://git.zx2c4.com/wireguard-go) by WireGuard LLC.

## Features

- Full userspace WireGuard daemon (upstream protocol implementation)
- Built-in REST API (Gin) for user/peer management
- Automatic server setup on Linux: keys, listen port, VPN IP, NAT, IP forwarding
- Client configs returned as standard WireGuard `.conf` text (base64 keys)
- Per-user bandwidth limiting via Linux traffic control (`tc` HTB + IFB)
- SQLite persistence for users and server key material

## Requirements

- Go 1.23.1+ to build
- Linux (recommended) for NAT, routing, and bandwidth limiting
- Root privileges to create the TUN device and configure networking
- `iptables` and/or `nftables` for NAT
- `tc` (iproute2) for bandwidth limits

## Build

```bash
git clone <your-repo-url>
cd wireguard-go
make
```

Cross-compile for Linux from another OS (requires a C toolchain because of SQLite):

```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o wireguard-go .
```

### CI / Releases

GitHub Actions runs automatically:

- **CI** (`.github/workflows/ci.yml`) — tests and builds on every push/PR to `master`/`main`
- **Release** (`.github/workflows/release.yml`) — on every `v*` tag, builds binaries and uploads them to a GitHub Release

Publish a new version:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Release assets:

| Asset | Platform |
|-------|----------|
| `wireguard-go-vX.Y.Z-linux-amd64` | Linux x86_64 |
| `wireguard-go-vX.Y.Z-linux-arm64` | Linux ARM64 |
| `wireguard-go-vX.Y.Z-darwin-amd64` | macOS Intel |
| `wireguard-go-vX.Y.Z-darwin-arm64` | macOS Apple Silicon |

Each binary ships with a matching `.sha256` checksum file.

## Quick start

```bash
sudo LOG_LEVEL=verbose ./wireguard-go -f wg0
```

On startup the daemon will:

1. Create (or recreate) the `wg0` interface
2. Generate and persist a server keypair (SQLite)
3. Listen on UDP `51820` (configurable)
4. Assign server VPN address `10.8.0.1/24`
5. Enable IP forwarding and NAT on the outbound interface
6. Start the management API on `:8080`

Example output:

```text
wireguard-go: server public key: FvknzsGeKgXYcUI5YuZKnWqMfZg2+kfWKIjbXI2WVR4=
wireguard-go: server VPN IP: 10.8.0.1
wireguard-go: listen port: 51820
wireguard-go: client endpoint: 153.80.240.160:51820
wireguard-go: NAT enabled (10.8.0.0/24 -> ens3)
wireguard-go: management API listening on :8080
```

Run in the background:

```bash
sudo ./wireguard-go wg0
```

Disable the management API:

```bash
sudo WG_API=0 ./wireguard-go -f wg0
```

## Configuration

Settings are loaded from `config.json` in the working directory (override with `WG_CONFIG`).

If the file is missing, it is created automatically with defaults and a random `secret_key`.
If `secret_key` is empty, a new one is generated and saved.

Example (`config.json.example`):

```json
{
  "api_enabled": true,
  "api_port": 8080,
  "secret_key": "",
  "listen_port": 51820,
  "subnet": "10.8.0.0/24",
  "server_ip": "10.8.0.1",
  "server_endpoint": "",
  "dns": "1.1.1.1",
  "out_interface": "",
  "keepalive_interval": 25,
  "db_path": "wireguard-wg0.db",
  "log_level": "verbose"
}
```

| Field | Description |
|-------|-------------|
| `api_enabled` | Enable management API |
| `api_port` | HTTP API port |
| `secret_key` | API auth key (`X-API-Key`); auto-generated if empty |
| `listen_port` | WireGuard UDP port |
| `subnet` | VPN address pool |
| `server_ip` | Server address inside the VPN |
| `server_endpoint` | Public `host:port` for client configs (auto-detected if empty) |
| `dns` | DNS written into client configs |
| `out_interface` | NIC used for NAT (auto-detected if empty) |
| `keepalive_interval` | Client persistent keepalive seconds |
| `db_path` | SQLite database path |
| `log_level` | Suggested log level (`verbose`, `error`, …) |

Environment variables still override matching `config.json` fields when set. Do not commit real `config.json` files (contains secrets).

## Environment variables

Environment variables are optional overrides. Prefer `config.json` for day-to-day settings.

## Management API

Base URL: `http://<server>:8080/api/v1`

If `API_KEY` is set, send it as:

```http
X-API-Key: <your-key>
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/users` | Create a user (peer + config) |
| `GET` | `/users` | List users |
| `GET` | `/users/:id` | Get user details + config |
| `PATCH` | `/users/:id` | Update name, bandwidth, or enabled flag |
| `DELETE` | `/users/:id` | Delete user and remove peer |
| `GET` | `/users/:id/config` | Fetch client config only |
| `GET` | `/users/:id/stats` | Peer transfer / handshake stats |

### Create a user

```bash
curl -X POST http://127.0.0.1:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","bandwidth_mbps":10}'
```

Response:

```json
{
  "id": "…",
  "name": "alice",
  "public_key": "…=",
  "private_key": "…=",
  "assigned_ip": "10.8.0.2",
  "bandwidth_mbps": 10,
  "enabled": true,
  "config": "[Interface]\nPrivateKey = …\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = …\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n",
  "created_at": "…",
  "updated_at": "…"
}
```

Import the `config` field into any official WireGuard client (Windows, macOS, Android, iOS, Linux).

Keys in API responses and client configs are **base64-encoded 32-byte** WireGuard keys.

### Update bandwidth limit

```bash
curl -X PATCH http://127.0.0.1:8080/api/v1/users/<id> \
  -H "Content-Type: application/json" \
  -d '{"bandwidth_mbps":50}'
```

Set `bandwidth_mbps` to `0` for unlimited.

### Disable / enable a peer

```bash
curl -X PATCH http://127.0.0.1:8080/api/v1/users/<id> \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}'
```

## Classic WireGuard usage

Without relying on the API, the daemon still speaks standard UAPI. You can manage peers with [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8):

```bash
sudo ./wireguard-go -f wg0
sudo wg set wg0 private-key ./server.key listen-port 51820
sudo ip addr add 10.8.0.1/24 dev wg0
sudo ip link set wg0 up
```

To stop the process when the interface cannot be deleted directly:

```bash
rm -f /var/run/wireguard/wg0.sock
```

## Project layout

```text
wireguard-go/
├── main.go              # Daemon entrypoint (+ management API hook)
├── device/              # WireGuard protocol core
├── conn/                # UDP bind / sockets
├── tun/                 # TUN drivers
├── ipc/                 # UAPI socket
├── mgmt/                # Management API (this fork)
│   ├── api/             # Gin HTTP handlers
│   ├── config/          # Env configuration
│   ├── peers/           # Key generation + device peer ops
│   ├── ratelimit/       # Per-user bandwidth limiting (Linux tc)
│   ├── setup/           # Auto iface / NAT / routing setup
│   └── store/           # SQLite persistence
└── …
```

## Platforms

| Platform | Daemon | Management API | Bandwidth limits | Auto NAT |
|----------|--------|----------------|------------------|----------|
| Linux | Yes | Yes | Yes (`tc`) | Yes |
| macOS | Yes | Limited | No | No |
| FreeBSD / OpenBSD | Yes | Limited | No | No |
| Windows | Test only | No | No | No |

For production Windows use, prefer [wireguard-windows](https://git.zx2c4.com/wireguard-windows/). On Linux, the kernel WireGuard module is usually faster; this userspace daemon is useful when you need the embedded management API or run outside kernel WG.

## Security notes

- Bind the API to a trusted network or protect it with `API_KEY` and a reverse proxy / firewall.
- Responses include client private keys by design (so configs are immediately usable). Treat the API as sensitive.
- Run as root only when necessary; protect the SQLite database (`DB_PATH`).
- Do not commit `*.db`, private keys, or production `API_KEY` values.

## License

Upstream wireguard-go is MIT-licensed:

```text
Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
```

See [`LICENSE`](LICENSE) for the full text. Management API additions in `mgmt/` are provided under the same MIT terms unless otherwise noted.
