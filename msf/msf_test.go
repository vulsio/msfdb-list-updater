package msf_test

import (
	"io/ioutil"
	"path"
	"reflect"
	"testing"

	"github.com/vulsio/msfdb-list-updater/models"
	"github.com/vulsio/msfdb-list-updater/msf"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file   string // Test input file
		module interface{}
	}{
		{
			file: "testdata/test_000.rb",
			module: &models.Module{
				Name:  "test_000.rb",
				Title: "Sample Module",
				References: []string{
					"https://github.com/rapid7/metasploit-framework/blob/master/testdata/test_000.rb",
				},
			},
		},
		{
			file: "testdata/test_001.rb",
			module: &models.Module{
				Name:        "test_001.rb",
				Title:       "Sample Exploit",
				Description: "This exploit module illustrates how a vulnerability could be exploited in an TCP server that has a parsing bug.",
				CveIDs:      []string{"CVE-1978-1234", "CVE-1978-5678"},
				EdbIDs:      []string{"EDB-12345"},
				References: []string{
					"http://cwe.mitre.org/data/definitions/123.html",
					"http://www.securityfocus.com/bid/12345",
					"http://www.zerodayinitiative.com/advisories/ZDI-12-345",
					"http://technet.microsoft.com/en-us/security/bulletin/MS12-345",
					"https://wpvulndb.com/vulnerabilities/12345",
					"http://www.kb.cert.org/vuls/id/12345",
					"https://packetstormsecurity.com/files/12345",
					"http://www.example.com",
					"https://github.com/rapid7/metasploit-framework/blob/master/testdata/test_001.rb",
				},
			},
		},
		{
			file: "testdata/test_002.rb",
			module: &models.Module{
				Name:        "test_002.rb",
				Title:       "Sample Auxiliary",
				Description: "Sample Auxiliary Module",
				References: []string{
					"https://github.com/rapid7/metasploit-framework/blob/master/testdata/test_002.rb",
				},
			},
		},
		{
			file: "testdata/test_003.rb",
			module: &models.Module{
				Name:        "test_003.rb",
				Title:       "Android Binder Use-After-Free Exploit",
				Description: "This module exploits CVE-2019-2215, which is a use-after-free in Binder in the Android kernel. The bug is a local privilege escalation vulnerability that allows for a full compromise of a vulnerable device. If chained with a browser renderer exploit, this bug could fully compromise a device through a malicious website. The freed memory is replaced with an iovec structure in order to leak a pointer to the task_struct. Finally the bug is triggered again in order to overwrite the addr_limit, making all memory (including kernel memory) accessible as part of the user-space memory range in our process and allowing arbitrary reading and writing of kernel memory.",
				CveIDs:      []string{"CVE-2019-2215"},
				References: []string{
					"https://bugs.chromium.org/p/project-zero/issues/detail?id=1942",
					"https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html",
					"https://hernan.de/blog/2019/10/15/tailoring-cve-2019-2215-to-achieve-root/",
					"https://github.com/grant-h/qu1ckr00t/blob/master/native/poc.c",
					"https://github.com/rapid7/metasploit-framework/blob/master/testdata/test_003.rb",
				},
			},
		},
		{
			file: "testdata/test_004.rb",
			module: &models.Module{
				Name:        "test_004.rb",
				Title:       "OpenEMR 5.0.1 Patch 6 SQLi Dump",
				Description: "This module exploits a SQLi vulnerability found in OpenEMR version 5.0.1 Patch 6 and lower. The vulnerability allows the contents of the entire database (with exception of log and task tables) to be extracted. This module saves each table as a `.csv` file in your loot directory and has been tested with OpenEMR 5.0.1 (3).",
				CveIDs:      []string{"CVE-2018-17179"},
				References: []string{
					"https://github.com/openemr/openemr/commit/3e22d11c7175c1ebbf3d862545ce6fee18f70617",
					"https://github.com/rapid7/metasploit-framework/blob/master/testdata/test_004.rb",
				},
			},
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := ioutil.ReadFile(v.file)
			if err != nil {
				t.Fatalf("ReadFile() error: %v", err)
			}

			module, err := msf.Parse(f, v.file)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(module, v.module) {
				t.Errorf("\n got:\n%#v\nwant:\n%#v", module, v.module)
			}
		})
	}
}

func TestFormatDescription(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{
			"",
			"",
		},
		{
			"text text",
			"text text",
		},
		{
			" text\n  text\n  text",
			"text text text",
		},
		{
			"\ttext\n \ttext\n \ttext\t",
			"text text text",
		},
	}

	for _, tt := range tests {
		actual := msf.FormatDescription(tt.in)
		if actual != tt.out {
			t.Errorf("\n got: %s\nwant: %s", tt.out, actual)
		}
	}
}

func TestFormatReferences(t *testing.T) {
	var tests = []struct {
		inType string
		inID   string
		out    string
	}{
		{
			"",
			"",
			"",
		},
		{
			"URL",
			"https://github.com/",
			"https://github.com/",
		},
		{
			"MSB",
			"MS12-345",
			"http://technet.microsoft.com/en-us/security/bulletin/MS12-345",
		},
		{
			"INVALID",
			"https://github.com/",
			"",
		},
	}

	for _, tt := range tests {
		actual := msf.FormatReferences(tt.inType, tt.inID)
		if actual != tt.out {
			t.Errorf("\n got: %s\nwant: %s", tt.out, actual)
		}
	}
}

func TestFormatModuleURL(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{
			"",
			"https://github.com/rapid7/metasploit-framework/blob/master",
		},
		{
			"User/Caches/msfdb-list-updater/metasploit-framework/modules/example.rb",
			"https://github.com/rapid7/metasploit-framework/blob/master/modules/example.rb",
		},
		{
			"modules/example.rb",
			"https://github.com/rapid7/metasploit-framework/blob/master/modules/example.rb",
		},
	}

	for _, tt := range tests {
		actual := msf.FormatModuleURL(tt.in)
		if actual != tt.out {
			t.Errorf("\n got: %s\nwant: %s", tt.out, actual)
		}
	}
}
