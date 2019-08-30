package main

import (
	"flag"
	"log"
	"os"

	"github.com/containous/traefik-migration/ingress"
)

type config struct {
	input  string
	output string
}

func main() {

	var cfg config
	flag.StringVar(&cfg.input, "input", "", "input")
	flag.StringVar(&cfg.output, "output", "", "output dir")

	flag.Parse()

	if len(cfg.input) == 0 || len(cfg.output) == 0 {
		flag.Usage()
		log.Fatal("You must specify an input and an output")
	}

	info, err := os.Stat(cfg.output)
	if err != nil {
		if !os.IsNotExist(err) {
			flag.Usage()
			log.Fatal(err)
		}
		err = os.MkdirAll(cfg.output, 0755)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		if !info.IsDir() {
			flag.Usage()
			log.Fatalf("output must be a directory")
		}
	}


	err = ingress.Convert(cfg.input, cfg.output)
	if err != nil {
		log.Fatal(err)
	}
}
