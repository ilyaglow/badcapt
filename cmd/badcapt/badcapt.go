package main

import (
	"errors"
	"flag"
	"log"

	"github.com/ilyaglow/badcapt"
	"github.com/olivere/elastic"
)

func main() {
	listenIface := flag.String("i", "", "Interface name to listen")
	elasticLoc := flag.String("e", "", "Elastic URL")
	flag.Parse()

	if *listenIface == "" {
		panic(errors.New("no iface provided"))
	}

	var funcs []func(*badcapt.Badcapt) error
	if *elasticLoc != "" {
		client, err := elastic.NewClient(
			elastic.SetURL(*elasticLoc),
			elastic.SetSniff(false),
		)
		if err != nil {
			panic(err)
		}
		funcs = append(funcs, badcapt.SetElastic(client))
	}
	bc, err := badcapt.New(funcs...)
	if err != nil {
		panic(err)
	}

	log.Fatal(bc.Listen(*listenIface))
}
