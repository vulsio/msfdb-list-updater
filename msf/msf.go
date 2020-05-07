package msf

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/vulsio/msfdb-list-updater/git"
	log "github.com/vulsio/msfdb-list-updater/log"
)

const (
	repoURL = "https://github.com/rapid7/metasploit-framework.git"
	msfDir  = "msf_modules"
)

var (
	repoDir string
	files   []string
)

// Config :
type Config struct {
	GitClient   git.Operations
	CacheDir    string
	VulnListDir string
}

// Update :
func (c Config) Update() (err error) {
	log.Infof("Fetching Metasploit framework...")
	repoDir = filepath.Join(c.CacheDir, "metasploit-framework")
	if _, err = c.GitClient.CloneOrPull(repoURL, repoDir); err != nil {
		return xerrors.Errorf("failed to clone alpine repository: %w", err)
	}

	log.Infof("Walking modules...")
	files, err := WalkDirTree(filepath.Join(repoDir, "modules"))
	if err != nil {
		log.Errorf("%s", err)
	}
	for _, file := range files {
		fmt.Println(file)
	}
	return nil
}

// WalkDirTree :
func WalkDirTree(root string) ([]string, error) {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
