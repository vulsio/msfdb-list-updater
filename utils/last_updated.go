package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
)

const (
	lastUpdatedFile = "last_updated.json"
)

// LastUpdated :
type LastUpdated map[string]time.Time

// SetLastUpdatedDate :
func SetLastUpdatedDate(dir string, lastUpdatedDate time.Time) error {
	b, err := json.MarshalIndent(LastUpdated{"msf": lastUpdatedDate}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, lastUpdatedFile), b, 0600); err != nil {
		return xerrors.Errorf("failed to write last updated date: %w", err)
	}

	return nil
}
