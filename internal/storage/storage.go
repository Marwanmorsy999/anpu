// Package storage persists scan results to a local SQLite database so
// users can list past scans (`anpu history`) and re-view a specific
// scan (`anpu show <scan-id>`) without re-running it.
package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	// Pure-Go SQLite driver: keeps builds CGO-free so ANPU compiles into
	// working executables on every platform without a C toolchain.
	_ "modernc.org/sqlite"

	"github.com/anpu-project/anpu/pkg/models"
)

const schema = `
CREATE TABLE IF NOT EXISTS scans (
	id TEXT PRIMARY KEY,
	target TEXT NOT NULL,
	profile TEXT NOT NULL,
	started_at TEXT NOT NULL,
	completed_at TEXT,
	status TEXT NOT NULL,
	risk_score REAL NOT NULL DEFAULT 0,
	warnings TEXT
);

CREATE TABLE IF NOT EXISTS targets (
	scan_id TEXT NOT NULL,
	url TEXT NOT NULL,
	host TEXT NOT NULL,
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS findings (
	id TEXT NOT NULL,
	scan_id TEXT NOT NULL,
	title TEXT NOT NULL,
	severity TEXT NOT NULL,
	confidence TEXT NOT NULL,
	category TEXT NOT NULL,
	url TEXT,
	risk_score REAL NOT NULL DEFAULT 0,
	data TEXT NOT NULL,
	PRIMARY KEY(id, scan_id),
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS evidence (
	finding_id TEXT NOT NULL,
	scan_id TEXT NOT NULL,
	observed TEXT,
	location TEXT,
	unavailable INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(finding_id, scan_id) REFERENCES findings(id, scan_id)
);

CREATE TABLE IF NOT EXISTS technologies (
	scan_id TEXT NOT NULL,
	name TEXT NOT NULL,
	category TEXT NOT NULL,
	version TEXT,
	confidence REAL NOT NULL DEFAULT 0,
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS endpoints (
	scan_id TEXT NOT NULL,
	url TEXT NOT NULL,
	category TEXT NOT NULL,
	method TEXT,
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_technologies_scan ON technologies(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
`

// Store wraps a SQLite database connection.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and
// ensures the schema exists.
func Open(path string) (*Store, error) {
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	// SQLite serializes writers; a single connection avoids transient
	// SQLITE_BUSY errors between the write transaction and read paths.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// SaveScan persists a full ScanSummary. It uses a transaction so a
// failure partway through doesn't leave partial data.
func (s *Store) SaveScan(summary *models.ScanSummary) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	warningsJSON, _ := json.Marshal(summary.Warnings)

	_, err = tx.Exec(`INSERT OR REPLACE INTO scans (id, target, profile, started_at, completed_at, status, risk_score, warnings)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		summary.ID, summary.Target, string(summary.Profile),
		summary.StartedAt.Format(time.RFC3339), summary.CompletedAt.Format(time.RFC3339),
		summary.Status, summary.RiskScore, string(warningsJSON))
	if err != nil {
		return fmt.Errorf("saving scan record: %w", err)
	}

	if _, err = tx.Exec(`DELETE FROM evidence WHERE scan_id = ?`, summary.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM findings WHERE scan_id = ?`, summary.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM technologies WHERE scan_id = ?`, summary.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM endpoints WHERE scan_id = ?`, summary.ID); err != nil {
		return err
	}

	for _, f := range summary.Findings {
		data, err := json.Marshal(f)
		if err != nil {
			return fmt.Errorf("marshaling finding %s: %w", f.ID, err)
		}
		_, err = tx.Exec(`INSERT INTO findings (id, scan_id, title, severity, confidence, category, url, risk_score, data)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, summary.ID, f.Title, string(f.Severity), string(f.Confidence), string(f.Category), f.URL, f.RiskScore, string(data))
		if err != nil {
			return fmt.Errorf("saving finding %s: %w", f.ID, err)
		}
		_, err = tx.Exec(`INSERT INTO evidence (finding_id, scan_id, observed, location, unavailable) VALUES (?, ?, ?, ?, ?)`,
			f.ID, summary.ID, f.Evidence.Observed, f.Evidence.Location, boolToInt(f.Evidence.Unavailable))
		if err != nil {
			return fmt.Errorf("saving evidence for %s: %w", f.ID, err)
		}
	}

	for _, t := range summary.Technologies {
		_, err = tx.Exec(`INSERT INTO technologies (scan_id, name, category, version, confidence) VALUES (?, ?, ?, ?, ?)`,
			summary.ID, t.Name, t.Category, t.Version, t.Confidence)
		if err != nil {
			return fmt.Errorf("saving technology %s: %w", t.Name, err)
		}
	}

	for _, e := range summary.Endpoints {
		_, err = tx.Exec(`INSERT INTO endpoints (scan_id, url, category, method) VALUES (?, ?, ?, ?)`,
			summary.ID, e.URL, string(e.Category), e.Method)
		if err != nil {
			return fmt.Errorf("saving endpoint %s: %w", e.URL, err)
		}
	}

	return tx.Commit()
}

// ScanListItem is a lightweight row for `anpu history`.
type ScanListItem struct {
	ID          string
	Target      string
	Profile     string
	StartedAt   string
	Status      string
	RiskScore   float64
	FindingsCnt int
}

// ListScans returns recent scans, most recent first.
func (s *Store) ListScans(limit int) ([]ScanListItem, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
		SELECT s.id, s.target, s.profile, s.started_at, s.status, s.risk_score,
		       (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) as fc
		FROM scans s
		ORDER BY s.started_at DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanListItem
	for rows.Next() {
		var item ScanListItem
		if err := rows.Scan(&item.ID, &item.Target, &item.Profile, &item.StartedAt, &item.Status, &item.RiskScore, &item.FindingsCnt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetScan reconstructs a full ScanSummary for a specific scan ID.
func (s *Store) GetScan(id string) (*models.ScanSummary, error) {
	row := s.db.QueryRow(`SELECT id, target, profile, started_at, completed_at, status, risk_score, warnings FROM scans WHERE id = ?`, id)

	var summary models.ScanSummary
	var profile, started, completed, warningsJSON string
	if err := row.Scan(&summary.ID, &summary.Target, &profile, &started, &completed, &summary.Status, &summary.RiskScore, &warningsJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no scan found with id %q", id)
		}
		return nil, err
	}
	summary.Profile = models.Profile(profile)
	summary.StartedAt, _ = time.Parse(time.RFC3339, started)
	summary.CompletedAt, _ = time.Parse(time.RFC3339, completed)
	if warningsJSON != "" {
		_ = json.Unmarshal([]byte(warningsJSON), &summary.Warnings)
	}

	rows, err := s.db.Query(`SELECT data FROM findings WHERE scan_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var f models.Finding
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			continue
		}
		summary.Findings = append(summary.Findings, f)
	}

	techRows, err := s.db.Query(`SELECT name, category, version, confidence FROM technologies WHERE scan_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer techRows.Close()
	for techRows.Next() {
		var t models.Technology
		if err := techRows.Scan(&t.Name, &t.Category, &t.Version, &t.Confidence); err != nil {
			return nil, err
		}
		summary.Technologies = append(summary.Technologies, t)
	}

	epRows, err := s.db.Query(`SELECT url, category, method FROM endpoints WHERE scan_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer epRows.Close()
	for epRows.Next() {
		var e models.Endpoint
		var cat string
		if err := epRows.Scan(&e.URL, &cat, &e.Method); err != nil {
			return nil, err
		}
		e.Category = models.EndpointCategory(cat)
		summary.Endpoints = append(summary.Endpoints, e)
	}

	summary.RecomputeSeverityCounts()
	return &summary, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// LatestScanForTarget returns the most recently completed scan for the given
// target URL, or nil if no scan exists. Only "completed" scans are considered
// so an in-progress or failed scan doesn't pollute the baseline.
func (s *Store) LatestScanForTarget(target string) (*models.ScanSummary, error) {
	row := s.db.QueryRow(`
		SELECT id FROM scans
		WHERE target = ? AND status = 'completed'
		ORDER BY completed_at DESC
		LIMIT 1`, target)

	var id string
	if err := row.Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying latest scan for %q: %w", target, err)
	}
	return s.GetScan(id)
}
