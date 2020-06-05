package msf_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/vulsio/msfdb-list-updater/msf"
	"golang.org/x/xerrors"
)

type MockGitConfig struct {
	mock.Mock
}

func (mgc MockGitConfig) CloneOrPull(a string, b string) (map[string]struct{}, error) {
	args := mgc.Called(a, b)
	return args.Get(0).(map[string]struct{}), args.Error(1)
}

func (mgc MockGitConfig) RemoteBranch(a string) ([]string, error) {
	args := mgc.Called(a)
	return args.Get(0).([]string), args.Error(1)
}

func (mgc MockGitConfig) Checkout(a string, b string) error {
	args := mgc.Called(a, b)
	return args.Error(0)
}

func TestParse(t *testing.T) {
	vectors := []struct {
		file   string // Test input file
		module interface{}
	}{
		{
			file: "testdata/metasploit-framework/modules/exploits/example.rb",
			module: &msf.MsfModule{
				Name:        "example.rb",
				Title:       "Sample Exploit",
				Discription: "This exploit module illustrates how a vulnerability could be exploited in an TCP server that has a parsing bug.",
				CveIDs:      []string{"CVE-1978-1234"},
				EdbIDs:      []string{"EDB-12345"},
				RefURLs: []string{
					"http://www.example.com",
				},
			},
		},
		{
			file: "testdata/metasploit-framework/modules/exploits/example_webapp.rb",
			module: &msf.MsfModule{
				Name:        "example_webapp.rb",
				Title:       "Sample Webapp Exploit",
				Discription: "This exploit module illustrates how a vulnerability could be exploited in a webapp.",
				CveIDs:      []string{"CVE-1978-1234"},
				EdbIDs:      []string{"EDB-12345"},
				RefURLs: []string{
					"http://www.example.com",
				},
			},
		},
		{
			file: "testdata/metasploit-framework/modules/exploits/android/local/binder_uaf.rb",
			module: &msf.MsfModule{
				Name:        "binder_uaf.rb",
				Title:       "Android Binder Use-After-Free Exploit",
				Discription: "This module exploits CVE-2019-2215, which is a use-after-free in Binder in the Android kernel. The bug is a local privilege escalation vulnerability that allows for a full compromise of a vulnerable device. If chained with a browser renderer exploit, this bug could fully compromise a device through a malicious website. The freed memory is replaced with an iovec structure in order to leak a pointer to the task_struct. Finally the bug is triggered again in order to overwrite the addr_limit, making all memory (including kernel memory) accessible as part of the user-space memory range in our process and allowing arbitrary reading and writing of kernel memory.",
				CveIDs:      []string{"CVE-2019-2215"},
				RefURLs: []string{
					"https://bugs.chromium.org/p/project-zero/issues/detail?id=1942",
					"https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html",
					"https://hernan.de/blog/2019/10/15/tailoring-cve-2019-2215-to-achieve-root/",
					"https://github.com/grant-h/qu1ckr00t/blob/master/native/poc.c",
				},
			},
		},
		{
			file: "testdata/metasploit-framework/modules/auxiliary/example.rb",
			module: &msf.MsfModule{
				Name:        "example.rb",
				Title:       "Sample Auxiliary Module",
				Discription: "Sample Auxiliary Module",
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

func TestConfigUpdate(t *testing.T) {
	type cloneOrPull struct {
		returnArg map[string]struct{}
		err       error
	}

	testCases := []struct {
		name        string
		cloneOrPull cloneOrPull
		wantErr     error
	}{
		{
			name: "git clone fails",
			cloneOrPull: cloneOrPull{
				returnArg: nil, err: errors.New("failed clone operation"),
			},
			wantErr: xerrors.Errorf("failed to clone metasploit-framework repository: %w", errors.New("failed clone operation")),
		},
	}

	cacheDir := "testdata"
	repoDir := filepath.Join(cacheDir, "metasploit-framework")
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vulnListDir, err := ioutil.TempDir("", "TestUpdate")
			assert.NoError(t, err)
			defer os.RemoveAll(vulnListDir)

			mockGitConfig := new(MockGitConfig)
			mockGitConfig.On("CloneOrPull", mock.Anything, repoDir).Return(
				tc.cloneOrPull.returnArg, tc.cloneOrPull.err)

			mc := msf.Config{
				GitClient:   mockGitConfig,
				CacheDir:    cacheDir,
				VulnListDir: vulnListDir,
			}
			fmt.Println(vulnListDir)

			err = mc.Update()
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				err = filepath.Walk(vulnListDir, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if info.IsDir() {
						return nil
					}

					paths := strings.Split(path, string(os.PathSeparator))
					assert.True(t, len(paths) > 3)

					golden := filepath.Join("testdata", "goldens",
						paths[len(paths)-3], paths[len(paths)-2], paths[len(paths)-1],
					)

					got, _ := ioutil.ReadFile(path)
					want, _ := ioutil.ReadFile(golden + ".golden")
					assert.Equal(t, string(want), string(got), "Rapid7 result json")
					return nil
				})
				assert.NoError(t, err)
			}
		})
	}
}
