package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	log "github.com/vulsio/msfdb-list-updater/log"
	"github.com/vulsio/msfdb-list-updater/utils"
)

// Operations :
type Operations interface {
	CloneOrPull(string, string) (map[string]struct{}, error)
	RemoteBranch(string) ([]string, error)
	Checkout(string, string) error
}

// Config :
type Config struct {
}

// CloneOrPull :
func (gc Config) CloneOrPull(url, repoPath string) (map[string]struct{}, error) {
	exists, err := utils.Exists(filepath.Join(repoPath, ".git"))
	if err != nil {
		return nil, err
	}

	updatedFiles := map[string]struct{}{}
	if exists {
		log.Infof("git pull             : %s", repoPath)
		files, err := pull(url, repoPath)
		if err != nil {
			return nil, xerrors.Errorf("git pull error: %w", err)
		}

		for _, filename := range files {
			updatedFiles[strings.TrimSpace(filename)] = struct{}{}
		}
	} else {
		log.Infof("git clone            : %s", repoPath)
		if err = os.MkdirAll(repoPath, 0700); err != nil {
			return nil, err
		}
		if err := clone(url, repoPath); err != nil {
			return nil, err
		}

		err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}
			updatedFiles[path] = struct{}{}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return updatedFiles, nil
}

func clone(url, repoPath string) error {
	commandAndArgs := []string{"clone", "--depth", "1", url, repoPath}
	cmd := exec.Command("git", commandAndArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("failed to clone: %w", err)
	}
	return nil
}

func pull(url, repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	remoteCmd := []string{"remote", "get-url", "--push", "origin"}
	output, err := utils.Exec("git", append(commandArgs, remoteCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git rev-list: %w", err)
	}
	remoteURL := strings.TrimSpace(output)
	if remoteURL != url {
		return nil, xerrors.Errorf("remote url is %s, target is %s", remoteURL, url)
	}

	revParseCmd := []string{"rev-list", "-n", "1", "--all"}
	output, err = utils.Exec("git", append(commandArgs, revParseCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git rev-list: %w", err)
	}
	commitHash := strings.TrimSpace(output)
	if len(commitHash) == 0 {
		log.Warnf("no commit yet")
		return nil, nil
	}

	pullCmd := []string{"pull", "origin", "master"}
	if _, err = utils.Exec("git", append(commandArgs, pullCmd...)); err != nil {
		return nil, xerrors.Errorf("error in git pull: %w", err)
	}

	fetchCmd := []string{"fetch", "--prune"}
	if _, err = utils.Exec("git", append(commandArgs, fetchCmd...)); err != nil {
		return nil, xerrors.Errorf("error in git fetch: %w", err)
	}

	diffCmd := []string{"diff", commitHash, "HEAD", "--name-only"}
	output, err = utils.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, err
	}
	updatedFiles := strings.Split(strings.TrimSpace(output), "\n")
	return updatedFiles, nil
}

// Commit :
func (gc Config) Commit(repoPath, targetPath, message string) error {
	commandArgs := generateGitArgs(repoPath)
	addCmd := []string{"add", filepath.Join(repoPath, targetPath)}
	if _, err := utils.Exec("git", append(commandArgs, addCmd...)); err != nil {
		return xerrors.Errorf("error in git add: %w", err)
	}

	commitCmd := []string{"commit", "--message", message}
	if _, err := utils.Exec("git", append(commandArgs, commitCmd...)); err != nil {
		return xerrors.Errorf("error in git commit: %w", err)
	}

	return nil
}

// Push :
func (gc Config) Push(url, repoPath, branch string) error {
	commandArgs := generateGitArgs(repoPath)
	remoteCmd := []string{"remote", "set-url", "origin", url}
	if _, err := utils.Exec("git", append(commandArgs, remoteCmd...)); err != nil {
		return xerrors.Errorf("error in set-url: %w", err)
	}

	pushCmd := []string{"push", "origin", branch}
	if _, err := utils.Exec("git", append(commandArgs, pushCmd...)); err != nil {
		return xerrors.Errorf("error in git push: %w", err)
	}
	return nil
}

// RemoteBranch :
func (gc Config) RemoteBranch(repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)
	branchCmd := []string{"branch", "--remote"}
	output, err := utils.Exec("git", append(commandArgs, branchCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git branch: %w", err)
	}
	return strings.Split(output, "\n"), nil
}

// Checkout :
func (gc Config) Checkout(repoPath string, branch string) error {
	commandArgs := generateGitArgs(repoPath)
	checkoutCmd := []string{"checkout", branch}
	_, err := utils.Exec("git", append(commandArgs, checkoutCmd...))
	if err != nil {
		return xerrors.Errorf("error in git checkout: %w", err)
	}
	return nil
}

// Status :
func (gc Config) Status(repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	statusCmd := []string{"status", "--porcelain"}
	output, err := utils.Exec("git", append(commandArgs, statusCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git status: %w", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

// DiffFile :
func DiffFile(repoPath string, hash, file string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	prevHash := fmt.Sprintf("%s^", hash)
	diffCmd := []string{"diff", "--unified=0", prevHash, hash, "--", file}
	output, err := utils.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git diff: %w", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

// DiffPrev :
func DiffPrev(repoPath string, hash string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	prevHash := fmt.Sprintf("%s^", hash)
	diffCmd := []string{"diff", "--name-only", prevHash, hash, "--"}
	output, err := utils.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, xerrors.Errorf("git diff previous commit: %w", err)
	}
	return strings.Split(output, "\n"), nil
}

// ShowFile :
func ShowFile(repoPath string, hash string, filename string) (string, error) {
	commandArgs := generateGitArgs(repoPath)

	showCmd := []string{"show", fmt.Sprintf("%s:%s", hash, filename)}
	output, err := utils.Exec("git", append(commandArgs, showCmd...))
	if err != nil {
		return "", xerrors.Errorf("git show: %w", err)
	}
	return output, nil
}

func generateGitArgs(repoPath string) []string {
	gitDir := filepath.Join(repoPath, ".git")
	return []string{"--git-dir", gitDir, "--work-tree", repoPath}
}
