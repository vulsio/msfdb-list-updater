package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/vulsio/msfdb-list-updater/models"
)

// Exists :
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return true, err
}

// SaveCVEPerYear :
func SaveCVEPerYear(dir string, cveID string, data models.Module) error {
	s := strings.Split(cveID, "-")
	if len(s) != 3 {
		return xerrors.Errorf("invalid CVE-ID format: %s\n", cveID)
	}

	yearDir := filepath.Join(dir, s[1])
	if err := os.MkdirAll(yearDir, os.ModePerm); err != nil {
		return err
	}

	filePath := filepath.Join(yearDir, fmt.Sprintf("%s.json", cveID))
	datas, err := ConvertModels(filePath, data)
	if err != nil {
		return err
	}

	if err := Write(filePath, datas); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

// Write :
func Write(filePath string, data models.Modules) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := unescapeJSONMarshal(data)
	if err != nil {
		return err
	}

	_, err = f.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func unescapeJSONMarshal(jsonRaw models.Modules) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(jsonRaw)
	return buffer.Bytes(), err
}

// Read :
func Read(filePath string) (models.Modules, error) {
	f, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var datas models.Modules
	err = json.Unmarshal(b, &datas)
	if err != nil {
		return nil, err
	}

	return datas, nil
}

// ConvertModels :
func ConvertModels(filePath string, data models.Module) (models.Modules, error) {
	exists, err := Exists(filePath)
	if err != nil {
		return nil, err
	}

	var datas models.Modules
	if exists {
		datas, err = Read(filePath)
		if err != nil {
			return nil, err
		}
	}
	datas = append(datas, data)

	return datas, nil
}
