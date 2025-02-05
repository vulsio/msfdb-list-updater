package msf

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	log "github.com/vulsio/msfdb-list-updater/log"
	"github.com/vulsio/msfdb-list-updater/models"
	"github.com/vulsio/msfdb-list-updater/utils"
)

const (
	repoURL = "https://github.com/rapid7/metasploit-framework/archive/refs/heads/master.tar.gz"
	msfDir  = "rapid7"
)

var (
	titleRegex     = regexp.MustCompile(`['|\"]Name['|\"]\s*=>\s*['|\"|\(](.+)['|\"|\)]`)
	summaryRegexp1 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*%q{([^}]*)}`)
	summaryRegexp2 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*%q\(([^}]*) \),`)
	summaryRegexp3 = regexp.MustCompile(`['|\"]Description['|\"]\s*=>\s*['|\"|\(]([\s\S]*?)['|\"|\)],\n`)
	cveIDRegexp    = regexp.MustCompile(`['|\"]CVE['|\"],\s+['|\"](\d{4})-(\d+)['|\"]`)
	edbIDRegexp    = regexp.MustCompile(`['|\"]EDB['|\"],\s+['|\"](\d+)['|\"]`)
	// osvdbRegexp  = regexp.MustCompile(`['|\"](OSVDB)['|\"],\s['|\"](\d+)['|\"]`)  // http://osvdb.org is closed
	cweRegexp    = regexp.MustCompile(`['|\"](CWE)['|\"],\s+['|\"](\d+)['|\"]`)
	bidRegexp    = regexp.MustCompile(`['|\"](BID)['|\"],\s+['|\"](\d+)['|\"]`)
	zdiRegexp    = regexp.MustCompile(`['|\"](ZDI)['|\"],\s+['|\"](\d{2}-\d+)['|\"]`)
	msbRegexp    = regexp.MustCompile(`['|\"](MSB)['|\"],\s+['|\"](MS\d{2}-\d+)['|\"]`)
	wpvdbRegexp  = regexp.MustCompile(`['|\"](WPVDB)['|\"],\s+['|\"](\d+)['|\"]`)
	uscertRegexp = regexp.MustCompile(`['|\"](US-CERT-VU)['|\"],\s+['|\"](\d+)['|\"]`)
	packetRegexp = regexp.MustCompile(`['|\"](PACKETSTORM)['|\"],\s+['|\"](\d+)['|\"]`)
	refRegexp    = regexp.MustCompile(`['|\"](URL)['|\"],\s+['|\"](\S+)['|\"]`)
)

// Update : Clone msf to the cache directory and search for the module recursively.
func Update() (err error) {
	log.Infof("Initialize directory...")
	if err := os.RemoveAll(filepath.Join(utils.VulnListDir(), msfDir)); err != nil {
		return xerrors.Errorf("error in rm -rf %s: %w", filepath.Join(utils.VulnListDir(), msfDir), err)
	}

	log.Infof("Fetching Metasploit framework...")
	resp, err := http.Get(repoURL)
	if err != nil {
		return xerrors.Errorf("error in get repository: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return xerrors.Errorf("error in get repository: error request response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("error in new gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.Errorf("error in next tar reader: %w", err)
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		filename := filepath.Join("metasploit-framework", strings.TrimPrefix(hdr.Name, "metasploit-framework-master"))

		if !strings.HasPrefix(filename, "metasploit-framework/modules/auxiliary") && !strings.HasPrefix(filename, "metasploit-framework/modules/exploits") {
			continue
		}

		if strings.HasPrefix(filepath.Base(filename), "example") {
			continue
		}

		bs, err := io.ReadAll(tr)
		if err != nil {
			return xerrors.Errorf("error in read from tar reader: %w", err)
		}

		m, err := Parse(bs, filepath.Join(utils.CacheDir(), filename))
		if err != nil {
			return xerrors.Errorf("error in parse: %w", err)
		}

		for _, cve := range m.CveIDs {
			if err = utils.SaveCVEPerYear(msfDir, cve, *m); err != nil {
				return xerrors.Errorf("error in save: %w", err)
			}
		}
	}

	return nil
}

// Parse : Extracts information from update_info of module as a regular expression.
func Parse(file []byte, path string) (*models.Module, error) {
	// Title
	var title string
	titleMatches := titleRegex.FindAllSubmatch(file, -1)
	// Substitute the first of the matched elements into the title
	for _, m := range titleMatches {
		if 1 < len(m) {
			title = string(m[1])
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
				decs = FormatDescription(string(m[1]))
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
			url := FormatReferences(string(m[1]), string(m[2]))
			links = append(links, url)
		}
	}

	// Module Repository URL
	moduleURL := FormatModuleURL(path)
	links = append(links, moduleURL)

	return &models.Module{
		Name:        filepath.Base(path),
		Title:       title,
		Description: decs,
		CveIDs:      cveIDs,
		EdbIDs:      edbIDs,
		References:  links,
	}, nil
}

// FormatDescription :
func FormatDescription(desc string) string {
	ss := []string{}
	scanner := bufio.NewScanner(strings.NewReader(desc))
	for scanner.Scan() {
		if s := strings.TrimSpace(scanner.Text()); s != "" {
			ss = append(ss, s)
		}
	}
	return strings.Join(ss, " ")
}

// FormatReferences :
func FormatReferences(refType string, refID string) string {
	var url string

	switch string(refType) {
	case "CWE":
		url = fmt.Sprintf("http://cwe.mitre.org/data/definitions/%s.html", refID)
	case "BID":
		url = fmt.Sprintf("http://www.securityfocus.com/bid/%s", refID)
	case "ZDI":
		url = fmt.Sprintf("http://www.zerodayinitiative.com/advisories/ZDI-%s", refID)
	case "MSB":
		url = fmt.Sprintf("http://technet.microsoft.com/en-us/security/bulletin/%s", refID)
	case "WPVDB":
		url = fmt.Sprintf("https://wpvulndb.com/vulnerabilities/%s", refID)
	case "US-CERT-VU":
		url = fmt.Sprintf("http://www.kb.cert.org/vuls/id/%s", refID)
	case "PACKETSTORM":
		url = fmt.Sprintf("https://packetstormsecurity.com/files/%s", refID)
	case "URL":
		url = refID
	}

	return url
}

// FormatModuleURL :
func FormatModuleURL(path string) string {
	// remove cache dir strings
	s := strings.SplitAfter(path, "metasploit-framework")
	u, _ := url.Parse("https://github.com/rapid7/metasploit-framework/blob/master")
	u.Path = filepath.Join(u.Path, s[len(s)-1])

	return u.String()
}
