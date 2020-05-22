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

const (
	repoURL = "https://github.com/rapid7/metasploit-framework.git"
	msfDir  = "msf"
)

var (
	repoDir        string
	files          []string
	titleRegex     = regexp.MustCompile(`['|\"]Name['|\"]\s*=>\s*['|\"|\(](.+)['|\"|\)]`)
	summaryRegexp1 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*%q{([^}]*)}`)
	summaryRegexp2 = regexp.MustCompile(`['|\"]Description['|\"][\s\S]*?['|\"|\)],\n`)
	cveIDRegexp    = regexp.MustCompile(`['|\"]CVE['|\"],\s['|\"](\d{4})-(\d+)['|\"]`)
	edbIDRegexp    = regexp.MustCompile(`['|\"]EDB['|\"],\s['|\"](\d+)['|\"]`)
	refURLRegexp   = regexp.MustCompile(`['|\"]URL['|\"],\s['|\"](\S+)['|\"]`)
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

		module, err := parse(f, path)
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

func parse(file []byte, path string) (module *MsfModule, err error) {
	module = &MsfModule{}

	// module name
	module.Name = filepath.Base(path)

	// module title
	var title string
	titleMatches := titleRegex.FindAllSubmatch(file, -1)
	for _, m := range titleMatches {
		if 1 < len(m) {
			title = fmt.Sprintf("%s", m[1])
		}
	}
	module.Title = title

	// module discription
	var summary string
	var sentence []string
	regxps := []*regexp.Regexp{
		summaryRegexp1,
		summaryRegexp2,
	}
	for _, re := range regxps {
		summaryMatches := re.FindAllSubmatch(file, -1)
		for _, m := range summaryMatches {
			if 1 < len(m) {
				summary = fmt.Sprintf(`%s`, m[1])
				lines := strings.Split(summary, "\n")
				for _, l := range lines {
					text := strings.Replace(strings.TrimSpace(l), "\n", "", -1)
					sentence = append(sentence, text)
				}
				summary = strings.Join(sentence[:], "")
			}
		}
	}
	module.Discription = summary

	// module cves
	var cveIDs []string
	cveMatches := cveIDRegexp.FindAllSubmatch(file, -1)
	for _, m := range cveMatches {
		if 2 < len(m) {
			cveID := fmt.Sprintf("CVE-%s-%s", m[1], m[2])
			cveIDs = append(cveIDs, cveID)
		}
	}
	module.CveIDs = cveIDs

	// module exploitdb
	var edbIDs []string
	edbMatches := edbIDRegexp.FindAllSubmatch(file, -1)
	for _, m := range edbMatches {
		if 1 < len(m) {
			edbID := fmt.Sprintf("EDB-%s", m[1])
			edbIDs = append(edbIDs, edbID)
		}
	}
	module.EdbIDs = edbIDs

	// module Referenses
	var refURLs []string
	urlMatches := refURLRegexp.FindAllSubmatch(file, -1)
	for _, m := range urlMatches {
		if 1 < len(m) {
			url := fmt.Sprintf("%s", m[1])
			refURLs = append(refURLs, url)
		}
	}
	module.RefURLs = refURLs

	return module, nil
}
