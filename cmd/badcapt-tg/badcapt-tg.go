package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

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
		j, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("json.Marshal: %w", err)
		}

		msg := tgbotapi.NewMessage(int64(*chatID), string(j))
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
