package main

import (
	"os"

	"github.com/drogonsec/drogonsec/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
