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
	"github.com/vulsio/msfdb-list-updater/models"
	"github.com/vulsio/msfdb-list-updater/utils"
)

const (
	repoURL = "https://github.com/rapid7/metasploit-framework.git"
	msfDir  = "rapid7"
)

var (
	repoDir        string
	titleRegex     = regexp.MustCompile(`['|\"]Name['|\"]\s*=>\s*['|\"|\(](.+)['|\"|\)]`)
	summaryRegexp1 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*%q{([^}]*)}`)
	summaryRegexp2 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*%q\(([^}]*) \),`)
	summaryRegexp3 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*['|\"|\(]([\s\S]*?)['|\"|\)],\n`)
	cveIDRegexp    = regexp.MustCompile(`['|\"]CVE['|\"],\s+['|\"](\d{4})-(\d+)['|\"]`)
	edbIDRegexp    = regexp.MustCompile(`['|\"]EDB['|\"],\s+['|\"](\d+)['|\"]`)
	// osvdbRegexp  = regexp.MustCompile(`['|\"](OSVDB)['|\"],\s['|\"](\d+)['|\"]`)  // http://osvdb.org is closed
	cweRegexp    = regexp.MustCompile(`['|\"](CWE)['|\"],\s+['|\"](\d+)['|\"]`)
	bidRegexp    = regexp.MustCompile(`['|\"](BID)['|\"],\s+['|\"](\d+)['|\"]"`)
	zdiRegexp    = regexp.MustCompile(`['|\"](ZDI)['|\"],\s+['|\"](\d{2}-\d+)['|\"]`)
	msbRegexp    = regexp.MustCompile(`['|\"](MSB)['|\"],\s+['|\"](MS\d{2}-\d+)['|\"]`)
	wpvdbRegexp  = regexp.MustCompile(`['|\"](WPVDB)['|\"],\s+['|\"](\d+)['|\"]`)
	uscertRegexp = regexp.MustCompile(`['|\"](US-CERT-VU)['|\"],\s+['|\"](\d+)['|\"]`)
	packetRegexp = regexp.MustCompile(`['|\"](PACKETSTORM)['|\"],\s+['|\"](\d+)['|\"]`)
	refRegexp    = regexp.MustCompile(`['|\"](URL)['|\"],\s+['|\"](\S+)['|\"]`)
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

	log.Infof("Initialize directory...")
	listDir := filepath.Join(utils.VulnListDir(), msfDir)
	exists, err := utils.Exists(listDir)
	if err != nil {
		log.Errorf("%s", err)
		return err
	}

	if exists {
		err := os.RemoveAll(listDir)
		if err != nil {
			log.Errorf("%s", err)
			return err
		}
	}

	log.Infof("Parsing modules...")
	for _, target := range []string{"modules/auxiliary", "modules/exploits"} {
		moduleList, err := WalkDirTree(filepath.Join(repoDir, target))
		if err != nil {
			log.Errorf("%s", err)
			return err
		}

		for _, m := range moduleList {
			for _, cve := range m.CveIDs {
				if err = utils.SaveCVEPerYear(msfDir, cve, m); err != nil {
					return xerrors.Errorf("error in save: %w", err)
				}
			}
		}
	}

	return nil
}

// WalkDirTree :
func WalkDirTree(root string) ([]models.Module, error) {
	modules := []models.Module{}

	err := filepath.Walk(root,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return xerrors.Errorf("file walk error: %w", err)
			}
			if info.IsDir() {
				return nil
			}

			// Exclude the sample code
			sample, err := filepath.Match("example*", info.Name())
			if err != nil {
				return xerrors.Errorf("error in file check: %w", err)
			}
			if sample {
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
			modules = append(modules, *module)

			return nil
		})
	if err != nil {
		return nil, xerrors.Errorf("error in walk: %w", err)
	}

	return modules, nil
}

// Parse : Extracts information from update_info of module as a regular expression.
func Parse(file []byte, path string) (*models.Module, error) {
	// Title
	var title string
	titleMatches := titleRegex.FindAllSubmatch(file, -1)
	// Substitute the first of the matched elements into the title
	for _, m := range titleMatches {
		if 1 < len(m) {
			title = fmt.Sprintf("%s", m[1])
			break
		}
	}

	// Description
	var decs string
	decsRegxps := []*regexp.Regexp{
		summaryRegexp1,
		summaryRegexp2,
		summaryRegexp3,
	}
	// Substitute the first of the matched elements into the decs
	for _, re := range decsRegxps {
		decsMatches := re.FindAllSubmatch(file, -1)
		for _, m := range decsMatches {
			if 1 < len(m) {
				decs = formatDescription(m)
				if decs != "" {
					break
				}
			}
		}
		if decs != "" {
			break
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
	urlRegxps := []*regexp.Regexp{
		cweRegexp,
		bidRegexp,
		zdiRegexp,
		msbRegexp,
		wpvdbRegexp,
		uscertRegexp,
		packetRegexp,
		refRegexp,
	}
	for _, re := range urlRegxps {
		urlMatches := re.FindAllSubmatch(file, -1)
		for _, m := range urlMatches {
			url := formatReferences(m)
			links = append(links, url)
		}
	}

	return &models.Module{
		Name:        filepath.Base(path),
		Title:       title,
		Description: decs,
		CveIDs:      cveIDs,
		EdbIDs:      edbIDs,
		References:  links,
	}, nil
}

func formatDescription(match [][]byte) string {
	var s []string

	text := fmt.Sprintf(`%s`, match[1])
	lines := strings.Split(text, "\n")
	for _, l := range lines {
		t := strings.Replace(strings.TrimSpace(l), "\n", "", -1)
		s = append(s, t)
	}
	text = strings.Join(s[:], " ")
	text = strings.TrimSpace(text)

	return text
}

func formatReferences(match [][]byte) string {
	var url string

	switch string(match[1]) {
	case "CWE":
		url = fmt.Sprintf("http://cwe.mitre.org/data/definitions/%s.html", match[2])
	case "BID":
		url = fmt.Sprintf("http://www.securityfocus.com/bid/%s", match[2])
	case "ZDI":
		url = fmt.Sprintf("http://www.zerodayinitiative.com/advisories/ZDI-%s", match[2])
	case "MSB":
		url = fmt.Sprintf("http://technet.microsoft.com/en-us/security/bulletin/%s", match[2])
	case "WPVDB":
		url = fmt.Sprintf("https://wpvulndb.com/vulnerabilities/%s", match[2])
	case "US-CERT-VU":
		url = fmt.Sprintf("http://www.kb.cert.org/vuls/id/%s", match[2])
	case "PACKETSTORM":
		url = fmt.Sprintf("https://packetstormsecurity.com/files/%s", match[2])
	case "URL":
		url = fmt.Sprintf("%s", match[2])
	}

	return url
}
