package msf

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/vulsio/msfdb-list-updater/git"
	log "github.com/vulsio/msfdb-list-updater/log"
	"github.com/vulsio/msfdb-list-updater/utils"
)

// Module : Structure that stores information to be acquired.
type Module struct {
	Name        string
	Title       string
	Discription string   `json:",omitempty"`
	CveIDs      []string `json:",omitempty"`
	EdbIDs      []string `json:",omitempty"`
	References  []string `json:",omitempty"`
}

const (
	repoURL = "https://github.com/rapid7/metasploit-framework.git"
	msfDir  = "rapid7"
)

var (
	repoDir        string
	files          []string
	titleRegex     = regexp.MustCompile(`['|\"]Name['|\"]\s*=>\s*['|\"|\(](.+)['|\"|\)]`)
	summaryRegexp1 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*%q{([^}]*)}`)
	summaryRegexp2 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*%q\(([^}]*)\),`)
	summaryRegexp3 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*['|\"|\(]([\s\S]*?)['|\"|\)],\n`)
	cveIDRegexp    = regexp.MustCompile(`['|\"]CVE['|\"],\s['|\"](\d{4})-(\d+)['|\"]`)
	edbIDRegexp    = regexp.MustCompile(`['|\"]EDB['|\"],\s['|\"](\d+)['|\"]`)
	refRegexp      = regexp.MustCompile(`['|\"]URL['|\"],\s['|\"](\S+)['|\"]`)
)

// Config : Config parameters used in Git.
type Config struct {
	GitClient   git.Operations
	CacheDir    string
	VulnListDir string
}

// Update : Clone msf to the cache directory and search for the module recursively.
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
	err := filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return xerrors.Errorf("file walk error: %w", err)
			}
			if info.IsDir() {
				return nil
			}

			m, err := filepath.Match("example*", info.Name())
			if err != nil {
				return xerrors.Errorf("error in file check: %w", err)
			}
			if m {
				return nil
			}

			f, err := ioutil.ReadFile(path)
			if err != nil {
				return xerrors.Errorf("error in file open: %w", err)
			}

			module, err := Parse(f, path)
			if err != nil {
				return xerrors.Errorf("error in parse: %w", err)
			}

			for _, cve := range module.CveIDs {
				if err = utils.SaveCVEPerYear(msfDir, cve, module); err != nil {
					return xerrors.Errorf("error in save: %w", err)
				}
			}

			return nil
		})
	if err != nil {
		return xerrors.Errorf("error in walk: %w", err)
	}

	return nil
}

// Parse : Extracts information from update_info of module as a regular expression.
func Parse(file []byte, path string) (*Module, error) {
	// Title
	var title string
	titleMatches := titleRegex.FindAllSubmatch(file, -1)
	for _, m := range titleMatches {
		if 1 < len(m) {
			title = fmt.Sprintf("%s", m[1])
		}
	}

	// Discription
	var decs string
	var s []string
	regxps := []*regexp.Regexp{
		summaryRegexp1,
		summaryRegexp2,
		summaryRegexp3,
	}
	for _, re := range regxps {
		decsMatches := re.FindAllSubmatch(file, -1)
		for _, m := range decsMatches {
			if 1 < len(m) {
				decs = fmt.Sprintf(`%s`, m[1])
				lines := strings.Split(decs, "\n")
				for _, l := range lines {
					t := strings.Replace(strings.TrimSpace(l), "\n", "", -1)
					s = append(s, t)
				}
				decs = strings.Join(s[:], " ")
				decs = strings.TrimSpace(decs)
			}
		}
	}

	// Cve id
	var cveIDs []string
	cveMatches := cveIDRegexp.FindAllSubmatch(file, -1)
	for _, m := range cveMatches {
		if 2 < len(m) {
			cveID := fmt.Sprintf("CVE-%s-%s", m[1], m[2])
			cveIDs = append(cveIDs, cveID)
		}
	}

	// Exploitdb unique id
	var edbIDs []string
	edbMatches := edbIDRegexp.FindAllSubmatch(file, -1)
	for _, m := range edbMatches {
		if 1 < len(m) {
			edbID := fmt.Sprintf("EDB-%s", m[1])
			edbIDs = append(edbIDs, edbID)
		}
	}

	// Referenses
	var links []string
	urlMatches := refRegexp.FindAllSubmatch(file, -1)
	for _, m := range urlMatches {
		if 1 < len(m) {
			u := fmt.Sprintf("%s", m[1])
			links = append(links, u)
		}
	}

	return &Module{
		Name:        filepath.Base(path),
		Title:       title,
		Discription: decs,
		CveIDs:      cveIDs,
		EdbIDs:      edbIDs,
		References:  links,
	}, nil
}
