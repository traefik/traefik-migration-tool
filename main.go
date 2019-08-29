package main

import (
	"flag"
	"log"
	"os"

	"github.com/containous/ingresstocrd/ingress"
)

type config struct {
	input string
	output string
}

func main() {

	var config config
	flag.StringVar(&config.input, "input", "", "input")
	flag.StringVar(&config.output, "output", "", "output")

	flag.Parse()

	if len(config.input) == 0 || len(config.output) == 0 {
		log.Fatal("You must specify an input and an ouput")
	}

	info, err := os.Stat(config.output)
	if err != nil {
		log.Fatal(err)
	}

	if !info.IsDir() {
		log.Fatalf("output must be a directory")
	}

	err= ingress.Convert(config.input, config.output)
	if err != nil {
		log.Fatal(err)
	}
}

