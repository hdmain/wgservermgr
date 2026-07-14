package store

type ServerConfig struct {
	PrivateKey string
	PublicKey  string
	ListenPort int
	ServerIP   string
}

func (s *Store) GetServerConfig() (*ServerConfig, error) {
	row := s.db.QueryRow(`SELECT private_key, public_key, listen_port, server_ip FROM server_config LIMIT 1`)
	var sc ServerConfig
	err := row.Scan(&sc.PrivateKey, &sc.PublicKey, &sc.ListenPort, &sc.ServerIP)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

func (s *Store) SaveServerConfig(sc *ServerConfig) error {
	_, err := s.db.Exec(`DELETE FROM server_config`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO server_config (private_key, public_key, listen_port, server_ip)
		VALUES (?, ?, ?, ?)`,
		sc.PrivateKey, sc.PublicKey, sc.ListenPort, sc.ServerIP,
	)
	return err
}
