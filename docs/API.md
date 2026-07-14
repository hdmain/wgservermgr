# API Reference

Base path: `/api/v1`  
Default listen address: `:8080`

Authentication (optional): send header `X-API-Key: <API_KEY>` when `API_KEY` is set.

## Health

### `GET /api/v1/health`

```json
{ "status": "ok" }
```

## Users

### `POST /api/v1/users`

Create a WireGuard peer, allocate a VPN IP, optionally apply a bandwidth limit, and return a ready-to-import client config.

Request:

```json
{
  "name": "alice",
  "bandwidth_mbps": 10
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | Unique user label |
| `bandwidth_mbps` | int | no | `0` = unlimited (default) |

Response `201`:

```json
{
  "id": "uuid",
  "name": "alice",
  "public_key": "base64…",
  "private_key": "base64…",
  "assigned_ip": "10.8.0.2",
  "bandwidth_mbps": 10,
  "enabled": true,
  "config": "[Interface]\n…",
  "created_at": "2026-07-14T00:00:00Z",
  "updated_at": "2026-07-14T00:00:00Z"
}
```

### `GET /api/v1/users`

List all users (includes `config` and keys).

### `GET /api/v1/users/:id`

Fetch a single user.

### `PATCH /api/v1/users/:id`

Partial update.

```json
{
  "name": "alice-renamed",
  "bandwidth_mbps": 25,
  "enabled": true
}
```

### `DELETE /api/v1/users/:id`

Removes the peer from WireGuard and deletes the database row.

```json
{ "deleted": true, "id": "uuid" }
```

### `GET /api/v1/users/:id/config`

```json
{
  "interface": "wg0",
  "config": "[Interface]\nPrivateKey = …\n…"
}
```

### `GET /api/v1/users/:id/stats`

```json
{
  "tx_bytes": 0,
  "rx_bytes": 0,
  "last_handshake_time_sec": 0,
  "last_handshake_time_nsec": 0
}
```

## Error format

```json
{ "error": "message" }
```

Common status codes: `400`, `401`, `404`, `409`, `500`, `502`.
