package store

import "time"

type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	PublicKey     string    `json:"public_key"`
	PrivateKey    string    `json:"private_key"`
	AssignedIP    string    `json:"assigned_ip"`
	BandwidthMbps int       `json:"bandwidth_mbps"`
	TCClassID     int       `json:"-"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CreateUserInput struct {
	Name          string `json:"name" binding:"required"`
	BandwidthMbps int    `json:"bandwidth_mbps"`
}

type UpdateUserInput struct {
	Name          *string `json:"name"`
	BandwidthMbps *int    `json:"bandwidth_mbps"`
	Enabled       *bool   `json:"enabled"`
}

type UserStats struct {
	TxBytes           uint64 `json:"tx_bytes"`
	RxBytes           uint64 `json:"rx_bytes"`
	LastHandshakeSec  int64  `json:"last_handshake_time_sec"`
	LastHandshakeNsec int64  `json:"last_handshake_time_nsec"`
}

type ClientConfig struct {
	Interface string `json:"interface"`
	Config    string `json:"config"`
}

type UserResponse struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	PublicKey     string    `json:"public_key"`
	PrivateKey    string    `json:"private_key"`
	AssignedIP    string    `json:"assigned_ip"`
	BandwidthMbps int       `json:"bandwidth_mbps"`
	Enabled       bool      `json:"enabled"`
	Config        string    `json:"config"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
