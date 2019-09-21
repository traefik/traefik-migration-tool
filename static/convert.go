package static

import (
	"io"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/containous/traefik/v2/pkg/config/static"
	"gopkg.in/yaml.v2"
)

type encoder interface {
	Encode(v interface{}) error
}

// Convert old static configuration file to the Traefik v2 static configuration files.
func Convert(oldFilename string, outputDir string) error {
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return err
	}

	oldCfg := Configuration{}

	_, err = toml.DecodeFile(oldFilename, &oldCfg)
	if err != nil {
		return err
	}

	newCfg := migrateConfiguration(oldCfg)

	err = writeFile(filepath.Join(outputDir, "new-traefik.yml"), func(w io.Writer) encoder {
		return yaml.NewEncoder(w)
	}, newCfg)
	if err != nil {
		return err
	}

	err = writeFile(filepath.Join(outputDir, "new-traefik.toml"), func(w io.Writer) encoder {
		return toml.NewEncoder(w)
	}, newCfg)
	if err != nil {
		return err
	}

	return nil
}

func writeFile(filename string, enc func(w io.Writer) encoder, newCfg static.Configuration) error {
	cfgFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = cfgFile.Close() }()

	return enc(cfgFile).Encode(newCfg)
}
