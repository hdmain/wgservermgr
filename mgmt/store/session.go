package store

import "time"

func (s *Store) SetSessionLock(id, endpoint string, activeAt time.Time) error {
	if activeAt.IsZero() {
		activeAt = time.Now().UTC()
	} else {
		activeAt = activeAt.UTC()
	}
	_, err := s.db.Exec(`
		UPDATE users SET locked_endpoint = ?, locked_last_active_at = ?, updated_at = ? WHERE id = ?`,
		endpoint, activeAt.Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339), id,
	)
	return err
}

func (s *Store) ClearSessionLock(id string) error {
	_, err := s.db.Exec(`
		UPDATE users SET locked_endpoint = '', locked_last_active_at = '', updated_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), id,
	)
	return err
}
