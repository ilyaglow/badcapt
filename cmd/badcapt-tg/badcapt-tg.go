package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/ilyaglow/badcapt"
)

func main() {
	listenIface := flag.String("i", "", "Interface name to listen")
	chatID := flag.Int("chat", 0, "Telegram chat ID to report log into")
	flag.Parse()

	if *listenIface == "" {
		panic(errors.New("no iface provided"))
	}

	bot, err := tgbotapi.NewBotAPI(os.Getenv("API_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	fn := func(ctx context.Context, rec *badcapt.Record) error {
		text := fmt.Sprintf(`srcip: %s
srcport: %d
dstip: %s
dstport: %d
layers: %s
timestamp: %s
tags: %s
payload: %s`, rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort, strings.Join(rec.Layers, ","), rec.Timestamp, strings.Join(rec.Tags, ","), rec.PayloadString)
		msg := tgbotapi.NewMessage(int64(*chatID), text)
		msg.DisableWebPagePreview = true
		_, err = bot.Send(msg)
		if err != nil {
			return fmt.Errorf("telegram send: %w", err)
		}
		return nil
	}

	bc, err := badcapt.New(badcapt.SetExportFunc(fn))
	if err != nil {
		panic(err)
	}

	log.Fatal(bc.Listen(*listenIface))
}
