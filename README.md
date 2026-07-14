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

Cross-compile for Linux from another OS:

```bash
GOOS=linux GOARCH=amd64 go build -o wireguard-go .
```

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

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WG_API` | enabled | Set to `0` to disable the API |
| `API_PORT` | `8080` | HTTP API listen port |
| `API_KEY` | empty | Optional API key (`X-API-Key` header) |
| `WG_LISTEN_PORT` | `51820` | WireGuard UDP listen port |
| `WG_SUBNET` | `10.8.0.0/24` | VPN address pool |
| `WG_SERVER_IP` | `10.8.0.1` | Server address inside the VPN subnet |
| `WG_SERVER_ENDPOINT` | auto | Public `host:port` written into client configs |
| `WG_DNS` | `1.1.1.1` | DNS servers written into client configs |
| `WG_OUT_INTERFACE` | auto | Outbound NIC used for NAT (e.g. `ens3`, `eth0`) |
| `WG_KEEPALIVE_INTERVAL` | `25` | Client persistent keepalive (seconds) |
| `DB_PATH` | `wireguard-<iface>.db` | SQLite database path |
| `LOG_LEVEL` | `error` | `verbose` / `debug` / `error` / `silent` |

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
