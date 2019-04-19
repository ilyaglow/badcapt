package main

import (
	"errors"
	"flag"
	"log"

	"github.com/ilyaglow/badcapt"
)

func main() {
	listenIface := flag.String("i", "", "Interface name to listen")
	elasticLoc := flag.String("e", "http://localhost:9200", "Elastic URL")
	debug := flag.Bool("d", false, "Debug mode, output to the screen")
	flag.Parse()

	if *listenIface == "" {
		panic(errors.New("no iface provided"))
	}

	var (
		err error
		bc  *badcapt.Badcapt
	)
	if *debug {
		bc, err = badcapt.New()
		if err != nil {
			panic(err)
		}
	} else {
		bc, err = badcapt.NewConfig(*elasticLoc)
		if err != nil {
			panic(err)
		}
	}

	log.Fatal(bc.Listen(*listenIface))
}
