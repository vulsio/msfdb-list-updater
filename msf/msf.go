package msf

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/vulsio/msfdb-list-updater/git"
	log "github.com/vulsio/msfdb-list-updater/log"
)

const (
	repoURL = "https://github.com/rapid7/metasploit-framework.git"
)

var (
	repoDir string
	files   []string

	cveIDRegexp1 = regexp.MustCompile(`\[\s*'CVE'\s*,\s*'(\d{4})[-–](\d{4,})\s*'\s*\]`)
	cveIDRegexp2 = regexp.MustCompile(`\[\s*'CVE'\s*=>\s*'(\d{4})[-–](\d{4,})\s*'\s*\]`)
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
		return xerrors.Errorf("failed to clone metasploit-framework repository: %w", err)
	}

	log.Infof("Walking modules...")
	for _, target := range []string{"modules/auxiliary", "modules/exploits"} {
		if err := WalkDirTree(filepath.Join(repoDir, target)); err != nil {
			log.Errorf("%s", err)
			return err
		}
	}

	return nil
}

// WalkDirTree :
func WalkDirTree(root string) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("file walk error: %w", err)
		}
		if info.IsDir() {
			return nil
		}

		f, err := ioutil.ReadFile(path)
		if err != nil {
			return xerrors.Errorf("error in file open: %w", err)
		}

		modules, err := parse(f, path)
		if err != nil {
			return xerrors.Errorf("error in parse: %w", err)
		}
		fmt.Println(modules)

		files = append(files, path)
		for _, file := range files {
			fmt.Println(file)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in walk: %w", err)
	}

	return nil
}

func parse(file []byte, path string) (modules *MsfModuleCVE, err error) {
	modules = &MsfModuleCVE{}
	modules.ModuleName = filepath.Base(path)

	regxps := []*regexp.Regexp{
		cveIDRegexp1,
		cveIDRegexp2,
	}

	for _, re := range regxps {
		results := re.FindAllSubmatch(file, -1)
		for _, matches := range results {
			if 2 < len(matches) {
				cveID := fmt.Sprintf("CVE-%s-%s", matches[1], matches[2])
				modules.CveID = cveID
			}
		}
	}

	return modules, nil
}
