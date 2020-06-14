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
			file: "testdata/metasploit-framework/modules/exploits/example.rb",
			module: &models.Module{
				Name:        "example.rb",
				Title:       "Sample Exploit",
				Discription: "This exploit module illustrates how a vulnerability could be exploited in an TCP server that has a parsing bug.",
				CveIDs:      []string{"CVE-1978-1234"},
				EdbIDs:      []string{"EDB-12345"},
				References: []string{
					"http://www.example.com",
				},
			},
		},
		{
			file: "testdata/metasploit-framework/modules/exploits/example_webapp.rb",
			module: &models.Module{
				Name:        "example_webapp.rb",
				Title:       "Sample Webapp Exploit",
				Discription: "This exploit module illustrates how a vulnerability could be exploited in a webapp.",
				CveIDs:      []string{"CVE-1978-1234"},
				EdbIDs:      []string{"EDB-12345"},
				References: []string{
					"http://www.example.com",
				},
			},
		},
		{
			file: "testdata/metasploit-framework/modules/exploits/android/local/binder_uaf.rb",
			module: &models.Module{
				Name:        "binder_uaf.rb",
				Title:       "Android Binder Use-After-Free Exploit",
				Discription: "This module exploits CVE-2019-2215, which is a use-after-free in Binder in the Android kernel. The bug is a local privilege escalation vulnerability that allows for a full compromise of a vulnerable device. If chained with a browser renderer exploit, this bug could fully compromise a device through a malicious website. The freed memory is replaced with an iovec structure in order to leak a pointer to the task_struct. Finally the bug is triggered again in order to overwrite the addr_limit, making all memory (including kernel memory) accessible as part of the user-space memory range in our process and allowing arbitrary reading and writing of kernel memory.",
				CveIDs:      []string{"CVE-2019-2215"},
				References: []string{
					"https://bugs.chromium.org/p/project-zero/issues/detail?id=1942",
					"https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html",
					"https://hernan.de/blog/2019/10/15/tailoring-cve-2019-2215-to-achieve-root/",
					"https://github.com/grant-h/qu1ckr00t/blob/master/native/poc.c",
				},
			},
		},
		{
			file: "testdata/metasploit-framework/modules/auxiliary/example.rb",
			module: &models.Module{
				Name:        "example.rb",
				Title:       "Sample Auxiliary Module",
				Discription: "Sample Auxiliary Module",
			},
		},
		{
			file: "testdata/metasploit-framework/modules/auxiliary/sqli/openemr/openemr_sqli_dump.rb",
			module: &models.Module{
				Name:        "openemr_sqli_dump.rb",
				Title:       "OpenEMR 5.0.1 Patch 6 SQLi Dump",
				Discription: "This module exploits a SQLi vulnerability found in OpenEMR version 5.0.1 Patch 6 and lower. The vulnerability allows the contents of the entire database (with exception of log and task tables) to be extracted. This module saves each table as a `.csv` file in your loot directory and has been tested with OpenEMR 5.0.1 (3).",
				CveIDs:      []string{"CVE-2018-17179"},
				References: []string{
					"https://github.com/openemr/openemr/commit/3e22d11c7175c1ebbf3d862545ce6fee18f70617",
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
				t.Errorf("\ngot:\n%#v,\nwant:\n%#v", module, v.module)
			}
		})
	}
}
