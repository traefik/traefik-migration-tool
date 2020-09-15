package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/traefik/traefik-migration-tool/acme"
	"github.com/traefik/traefik-migration-tool/ingress"
	"github.com/traefik/traefik-migration-tool/static"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var Version = "dev"
var ShortCommit = ""
var Date = ""

type acmeConfig struct {
	input        string
	output       string
	resolverName string
}

type ingressConfig struct {
	input  string
	output string
}

type staticConfig struct {
	input     string
	outputDir string
}

func main() {
	log.SetFlags(log.Lshortfile)

	rootCmd := &cobra.Command{
		Use:     "traefik-migration-tool",
		Short:   "A tool to migrate from Traefik v1 to Traefik v2.",
		Long:    `A tool to migrate from Traefik v1 to Traefik v2.`,
		Version: Version,
	}

	var ingressCfg ingressConfig

	ingressCmd := &cobra.Command{
		Use:   "ingress",
		Short: "Migrate 'Ingress' to Traefik 'IngressRoute' resources.",
		Long:  "Migrate 'Ingress' to Traefik 'IngressRoute' resources.",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("Traefik Migration: %s - %s - %s\n", Version, Date, ShortCommit)

			if len(ingressCfg.input) == 0 || len(ingressCfg.output) == 0 {
				return errors.New("input and output flags are requires")
			}

			info, err := os.Stat(ingressCfg.output)
			if err != nil {
				if !os.IsNotExist(err) {
					return err
				}
				err = os.MkdirAll(ingressCfg.output, 0755)
				if err != nil {
					return err
				}
			} else if !info.IsDir() {
				return errors.New("output must be a directory")
			}

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return ingress.Convert(ingressCfg.input, ingressCfg.output)
		},
	}

	ingressCmd.Flags().StringVarP(&ingressCfg.input, "input", "i", "", "Input directory.")
	ingressCmd.Flags().StringVarP(&ingressCfg.output, "output", "o", "./output", "Output directory.")

	rootCmd.AddCommand(ingressCmd)

	acmeCfg := acmeConfig{}

	acmeCmd := &cobra.Command{
		Use:   "acme",
		Short: "Migrate acme.json file from Traefik v1 to Traefik v2.",
		Long:  "Migrate acme.json file from Traefik v1 to Traefik v2.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return acme.Convert(acmeCfg.input, acmeCfg.output, acmeCfg.resolverName)
		},
	}

	acmeCmd.Flags().StringVarP(&acmeCfg.input, "input", "i", "./acme.json", "Path to the acme.json file from Traefik v1.")
	acmeCmd.Flags().StringVarP(&acmeCfg.output, "output", "o", "./acme-new.json", "Path to the acme.json file for Traefik v2.")
	acmeCmd.Flags().StringVar(&acmeCfg.resolverName, "resolver", "default", "The name of the certificates resolver.")

	rootCmd.AddCommand(acmeCmd)

	staticCfg := staticConfig{}

	staticCmd := &cobra.Command{
		Use:   "static",
		Short: "Migrate static configuration file from Traefik v1 to Traefik v2.",
		Long: `Migrate static configuration file from Traefik v1 to Traefik v2.
Convert only the static configuration.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return static.Convert(staticCfg.input, staticCfg.outputDir)
		},
	}

	staticCmd.Flags().StringVarP(&staticCfg.input, "input", "i", "./traefik.toml", "Path to the traefik.toml file from Traefik v1.")
	staticCmd.Flags().StringVarP(&staticCfg.outputDir, "output-dir", "d", "./static", "Path to the directory of the created files")

	rootCmd.AddCommand(staticCmd)

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
