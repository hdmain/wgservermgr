package store

import (
	"database/sql"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db     *sql.DB
	subnet netip.Prefix
}

func Open(path, subnet string) (*Store, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	s := &Store{db: db, subnet: prefix}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			public_key TEXT NOT NULL UNIQUE,
			private_key TEXT NOT NULL,
			assigned_ip TEXT NOT NULL UNIQUE,
			bandwidth_mbps INTEGER NOT NULL DEFAULT 0,
			tc_class_id INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS server_config (
			private_key TEXT NOT NULL,
			public_key TEXT NOT NULL,
			listen_port INTEGER NOT NULL,
			server_ip TEXT NOT NULL
		);
	`)
	return err
}

func (s *Store) Create(input CreateUserInput, publicKey, privateKey string) (*User, error) {
	ip, classID, err := s.allocateIP()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	user := &User{
		ID:            uuid.NewString(),
		Name:          input.Name,
		PublicKey:     publicKey,
		PrivateKey:    privateKey,
		AssignedIP:    ip,
		BandwidthMbps: input.BandwidthMbps,
		TCClassID:     classID,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	_, err = s.db.Exec(`
		INSERT INTO users (id, name, public_key, private_key, assigned_ip, bandwidth_mbps, tc_class_id, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Name, user.PublicKey, user.PrivateKey, user.AssignedIP,
		user.BandwidthMbps, user.TCClassID, boolToInt(user.Enabled),
		user.CreatedAt.Format(time.RFC3339), user.UpdatedAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

func (s *Store) List() ([]User, error) {
	rows, err := s.db.Query(`
		SELECT id, name, public_key, private_key, assigned_ip, bandwidth_mbps, tc_class_id, enabled, created_at, updated_at
		FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *user)
	}
	return users, rows.Err()
}

func (s *Store) Get(id string) (*User, error) {
	row := s.db.QueryRow(`
		SELECT id, name, public_key, private_key, assigned_ip, bandwidth_mbps, tc_class_id, enabled, created_at, updated_at
		FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func (s *Store) Update(id string, input UpdateUserInput) (*User, error) {
	user, err := s.Get(id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		user.Name = *input.Name
	}
	if input.BandwidthMbps != nil {
		user.BandwidthMbps = *input.BandwidthMbps
	}
	if input.Enabled != nil {
		user.Enabled = *input.Enabled
	}
	user.UpdatedAt = time.Now().UTC()

	_, err = s.db.Exec(`
		UPDATE users SET name = ?, bandwidth_mbps = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		user.Name, user.BandwidthMbps, boolToInt(user.Enabled), user.UpdatedAt.Format(time.RFC3339), id,
	)
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	return user, nil
}

func (s *Store) Delete(id string) (*User, error) {
	user, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("delete user: %w", err)
	}
	return user, nil
}

func (s *Store) allocateIP() (string, int, error) {
	used := make(map[uint32]bool)
	rows, err := s.db.Query(`SELECT assigned_ip FROM users`)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return "", 0, err
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		used[ipToHost(addr)] = true
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}

	base := s.subnet.Addr().As4()
	maxHosts := uint32(1<<(32-s.subnet.Bits()) - 2)
	for host := uint32(2); host <= maxHosts; host++ {
		if used[host] {
			continue
		}
		addr := netip.AddrFrom4([4]byte{
			base[0], base[1], base[2], byte(host),
		})
		return addr.String(), int(host), nil
	}
	return "", 0, fmt.Errorf("no available IPs in subnet %s", s.subnet)
}

func ipToHost(addr netip.Addr) uint32 {
	a := addr.As4()
	return uint32(a[3])
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*User, error) {
	var user User
	var enabled int
	var createdAt, updatedAt string
	err := row.Scan(
		&user.ID, &user.Name, &user.PublicKey, &user.PrivateKey, &user.AssignedIP,
		&user.BandwidthMbps, &user.TCClassID, &enabled, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	user.Enabled = enabled == 1
	user.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, err
	}
	user.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
