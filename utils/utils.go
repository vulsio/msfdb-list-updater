package utils

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

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
