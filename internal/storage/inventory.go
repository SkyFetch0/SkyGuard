package storage

import "time"

// Inventory returns every stored target as key → JSON.
func (d *DB) Inventory() (map[string]string, error) {
	rows, err := d.db.Query(`SELECT key, data FROM inventory`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SaveInventory stores one target's scan.
func (d *DB) SaveInventory(key, data string) error {
	_, err := d.db.Exec(`INSERT INTO inventory (key, data, scanned_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET data = excluded.data, scanned_at = excluded.scanned_at`, key, data, formatTS(time.Now()))
	return err
}

// DeleteInventory forgets a target that is gone.
func (d *DB) DeleteInventory(key string) error {
	_, err := d.db.Exec(`DELETE FROM inventory WHERE key = ?`, key)
	return err
}

// GetVuln returns a cached OSV advisory.
func (d *DB) GetVuln(id string) (data, modified string, ok bool) {
	err := d.db.QueryRow(`SELECT data, modified FROM vuln_cache WHERE id = ?`, id).Scan(&data, &modified)
	return data, modified, err == nil
}

// PutVuln caches an OSV advisory.
func (d *DB) PutVuln(id, modified, data string) error {
	_, err := d.db.Exec(`INSERT INTO vuln_cache (id, modified, data, fetched_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET modified = excluded.modified, data = excluded.data, fetched_at = excluded.fetched_at`,
		id, modified, data, formatTS(time.Now()))
	return err
}

const keyInventoryOSV = "inventory_osv"

// InventoryOSV reports whether versions may be sent to OSV.dev.
func (d *DB) InventoryOSV() bool {
	v, ok, err := d.getSetting(keyInventoryOSV)
	return err == nil && ok && v == "1"
}

// SetInventoryOSV stores that choice.
func (d *DB) SetInventoryOSV(on bool) error { return d.setSetting(keyInventoryOSV, boolToStr(on)) }
