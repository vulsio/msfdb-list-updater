package msf_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/xerrors"
	"github.com/vulsio/msfdb-list-updater/msf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestUpdate(t *testing.T) {
	type cloneOrPull struct {
		returnArg map[string]struct{}
		err       error
	}

	testCases := []struct {
		name         string
		cloneOrPull  cloneOrPull
		wantErr      error
	}{
		{
			name: "git clone fails",
			cloneOrPull: cloneOrPull{
				returnArg: nil, err: errors.New("failed clone operation"),
			},
			wantErr:  xerrors.Errorf("failed to clone metasploit-framework repository: %w", errors.New("failed clone operation")),
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