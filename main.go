package main

import (
	"flag"
	"os"
	"time"

	"golang.org/x/xerrors"

	log "github.com/vulsio/msfdb-list-updater/log"
	"github.com/vulsio/msfdb-list-updater/msf"
	"github.com/vulsio/msfdb-list-updater/utils"
)

var (
	target = flag.String("target", "", "update target (msf)")
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("%s", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func run() error {
	flag.Parse()
	now := time.Now().UTC()

	switch *target {
	case "msf":
		if err := msf.Update(); err != nil {
			return xerrors.Errorf("error in module update: %w", err)
		}
	default:
		return xerrors.New("unknown target")
	}

	if err := utils.SetLastUpdatedDate(*target, now); err != nil {
		return err
	}

	return nil
}
