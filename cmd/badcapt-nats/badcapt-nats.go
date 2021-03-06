package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ilyaglow/badcapt"
	stan "github.com/nats-io/stan.go"
)

func main() {
	listenIface := flag.String("i", "", "Interface name to listen")
	natsURL := flag.String("nats", os.Getenv("NATS_URL"), "NATS URL")
	clientID := flag.String("id", os.Getenv("CLIENT_ID"), "NATS client id")
	timeout := flag.Duration("t", 2*time.Second, "Publish to NATS timeout")
	flag.Parse()

	if *listenIface == "" {
		panic(errors.New("no iface provided"))
	}

	sc, err := stan.Connect(
		"test-cluster",
		*clientID,
		stan.NatsURL(*natsURL),
		stan.PubAckWait(*timeout),
		stan.SetConnectionLostHandler(func(_ stan.Conn, reason error) {
			log.Fatalf("connection lost, reason: %v", reason)
		}))
	if err != nil {
		log.Fatal(err)
	}

	fn := func(ctx context.Context, rec *badcapt.Record) error {
		j, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("json.Marshal: %w", err)
		}
		return sc.Publish("logs.v0", j)
	}

	bc, err := badcapt.New(badcapt.SetExportFunc(fn))
	if err != nil {
		panic(err)
	}

	log.Fatal(bc.Listen(*listenIface))
}
