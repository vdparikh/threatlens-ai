package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/vdparikh/ThreatLensAI/engine/internal/analyze"
	"github.com/vdparikh/ThreatLensAI/engine/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var configPath string
	flag.StringVar(&configPath, "config", "", "optional path to JSON config (defaults to <root>/.threatlensai.json)")
	flag.Parse()
	args := flag.Args()
	root := "."
	if len(args) > 0 {
		root = args[0]
	}

	var cfg config.Config
	var err error
	if configPath != "" {
		cfg, err = config.FromJSONFile(root, configPath)
	} else {
		cfg, err = config.FromRoot(root)
	}
	if err != nil {
		return err
	}

	model, err := analyze.BuildSystemModel(cfg)
	if err != nil {
		if errors.Is(err, fs.ErrInvalid) {
			return fmt.Errorf("root is not a directory: %s", cfg.Root)
		}
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(model); err != nil {
		return err
	}
	return nil
}
