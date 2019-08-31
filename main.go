package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/containous/traefik-migration/ingress"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var Version = "dev"
var ShortCommit = ""
var Date = ""

type config struct {
	input  string
	output string
}

func main() {
	log.SetFlags(log.Lshortfile)

	var cfg config

	rootCmd := &cobra.Command{
		Use:     "traefik-migration",
		Short:   "A tool to migrate 'Ingress' to Traefik 'IngressRoute' resources.",
		Long:    `A tool to migrate 'Ingress' to Traefik 'IngressRoute' resources.`,
		Version: Version,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("Traefik Migration: %s - %s - %s\n", Version, Date, ShortCommit)

			if len(cfg.input) == 0 || len(cfg.output) == 0 {
				return errors.New("input and output flags are requires")
			}

			info, err := os.Stat(cfg.output)
			if err != nil {
				if !os.IsNotExist(err) {
					return err
				}
				err = os.MkdirAll(cfg.output, 0755)
				if err != nil {
					return err
				}
			} else {
				if !info.IsDir() {
					return errors.New("output must be a directory")
				}
			}

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return ingress.Convert(cfg.input, cfg.output)
		},
	}

	flags := rootCmd.Flags()
	flags.StringVar(&cfg.input, "input", "", "Input directory")
	flags.StringVar(&cfg.output, "output", "./output", "Output directory")

	docCmd := &cobra.Command{
		Use:    "doc",
		Short:  "Generate documentation",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doc.GenMarkdownTree(rootCmd, "./docs")
		},
	}

	rootCmd.AddCommand(docCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Display version",
		Run: func(_ *cobra.Command, _ []string) {
			displayVersion(rootCmd.Name())
		},
	}

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func displayVersion(name string) {
	fmt.Printf(name+`:
 version     : %s
 commit      : %s
 build date  : %s
 go version  : %s
 go compiler : %s
 platform    : %s/%s
`, Version, ShortCommit, Date, runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
}
