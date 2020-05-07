package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/vulsio/msfdb-list-updater/git"
	log "github.com/vulsio/msfdb-list-updater/log"
	"github.com/vulsio/msfdb-list-updater/msf"
	"github.com/vulsio/msfdb-list-updater/utils"
)

const (
	repoURL          = "https://%s@github.com/%s/%s.git"
	defaultRepoOwner = "vulsio"
	defaultRepoName  = "msfdb-list"
)

var (
	target = flag.String("target", "", "update target (msf)")
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%s", err)
	}
}

func run() error {
	flag.Parse()
	now := time.Now().UTC()
	gc := &git.Config{}
	vulnListDir := utils.VulnListDir()

	repoOwner := defaultRepoOwner
	repoName := defaultRepoName

	// Embed GitHub token to URL
	githubToken := os.Getenv("GITHUB_TOKEN")
	url := fmt.Sprintf(repoURL, githubToken, repoOwner, repoName)

	log.Infof("target repository is %s/%s", repoOwner, repoName)

	if _, err := gc.CloneOrPull(url, utils.VulnListDir()); err != nil {
		return xerrors.Errorf("clone or pull error: %w", err)
	}

	// var commitMsg string
	switch *target {
	case "msf":
		// TODO : Call msf module parser
		mf := msf.Config{
			GitClient:   gc,
			CacheDir:    utils.CacheDir(),
			VulnListDir: vulnListDir,
		}
		if err := mf.Update(); err != nil {
			return xerrors.Errorf("error in module update: %w", err)
		}
		// commitMsg = "MSF modules"
	default:
		return xerrors.New("unknown target")
	}

	if err := utils.SetLastUpdatedDate(*target, now); err != nil {
		return err
	}

	log.Infof("git status")
	files, err := gc.Status(utils.VulnListDir())
	if err != nil {
		return xerrors.Errorf("failed to git status: %w", err)
	}

	// only last_updated.json
	if len(files) < 2 {
		log.Infof("Skip commit and push")
		return nil
	}

	// log.Println("git commit")
	// if err = gc.Commit(utils.VulnListDir(), "./", commitMsg); err != nil {
	// 	return xerrors.Errorf("failed to git commit: %w", err)
	// }

	// log.Println("git push")
	// if err = gc.Push(utils.VulnListDir(), "master"); err != nil {
	// 	return xerrors.Errorf("failed to git push: %w", err)
	// }

	return nil
}
