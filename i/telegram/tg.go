package telegram

import (
	"net/http"

	tgbotapi "github.com/aerth/webd/i/telegram/bot"
)

type UpdatesChannel = tgbotapi.UpdatesChannel
type Bot struct {
	T       *tgbotapi.BotAPI
	updates tgbotapi.UpdatesChannel
}

var NewMessage = tgbotapi.NewMessage

func New(key string) (*Bot, error) {
	var client = &http.Client{}
	t, err := tgbotapi.NewBotAPIWithClient(key, tgbotapi.APIEndpoint, client)
	if err != nil {
		return nil, err
	}
	return &Bot{T: t}, nil
}

func (b *Bot) Close() error {
	b.T.Debug = true
	b.T.StopReceivingUpdates()
	return nil
}
func (b *Bot) UpdateChan() tgbotapi.UpdatesChannel {
	return b.updates
}
func (b *Bot) Start() error {
	updates, err := b.T.GetUpdatesChan(tgbotapi.UpdateConfig{})
	if err != nil {
		return err
	}
	b.updates = updates
	return nil
}
