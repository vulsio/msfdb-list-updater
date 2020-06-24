package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulsio/msfdb-list-updater/models"
	"golang.org/x/xerrors"
)

// CacheDir :
func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "msfdb-list-updater")
	return dir
}

// VulnListDir :
func VulnListDir() string {
	return filepath.Join(CacheDir(), "msfdb-list")
}

// GenWorkers : generate workders
func GenWorkers(num, wait int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			for f := range tasks {
				f()
				time.Sleep(time.Duration(wait) * time.Second)
			}
		}()
	}
	return tasks
}

// Exists :
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// Exec :
func Exec(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		log.Println(stderrBuf.String())
		return "", xerrors.Errorf("failed to exec: %w", err)
	}
	return stdoutBuf.String(), nil
}

// LookupEnv :
func LookupEnv(key, defaultValue string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultValue
}

// SaveCVEPerYear :
func SaveCVEPerYear(dirName string, cveID string, data models.Module) error {
	s := strings.Split(cveID, "-")
	if len(s) != 3 {
		return xerrors.Errorf("invalid CVE-ID format: %s\n", cveID)
	}

	yearDir := filepath.Join(VulnListDir(), dirName, s[1])
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

	b, err := ioutil.ReadAll(f)
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
