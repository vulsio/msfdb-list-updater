package main

import (
	"os"

	"golang.org/x/xerrors"

	log "github.com/vulsio/msfdb-list-updater/log"
	"github.com/vulsio/msfdb-list-updater/msf"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("%s", "[usage] go run main.go <msfdb-list path>")
		os.Exit(1)
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatalf("%s", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func run(args string) error {
	if err := msf.Update(args); err != nil {
		return xerrors.Errorf("error in module update: %w", err)
	}
	return nil
}
