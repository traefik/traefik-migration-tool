package main

import (
	"flag"
	"log"
	"os"

	"github.com/containous/ingresstocrd/ingress"
)

type config struct {
	input  string
	output string
}

func main() {

	var cfg config
	flag.StringVar(&cfg.input, "input", "", "input")
	flag.StringVar(&cfg.output, "output", "", "output")

	flag.Parse()

	if len(cfg.input) == 0 || len(cfg.output) == 0 {
		log.Fatal("You must specify an input and an ouput")
	}

	info, err := os.Stat(cfg.output)
	if err != nil {
		log.Fatal(err)
	}

	if !info.IsDir() {
		log.Fatalf("output must be a directory")
	}

	err = ingress.Convert(cfg.input, cfg.output)
	if err != nil {
		log.Fatal(err)
	}
}
