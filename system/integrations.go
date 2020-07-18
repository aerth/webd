package system

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aerth/webd/i/telegram"
)

type Integrations struct {
	tg        *telegram.Bot           // main tg connection
	tgupdates telegram.UpdatesChannel // recv updates from tg
	tgsend    func(s string) error    // send message directly to administrator
}

func startTelegramLoop(s *System) {
	l := log.New(os.Stderr, "[telegram] ", log.LstdFlags)
	if s.config.Meta.DevelopmentMode {
		l.SetFlags(log.Lshortfile | log.LstdFlags)
	}
	t := s.i.tg.T
	updates := s.i.tgupdates
	adminchat := s.config.Telegram.AdminChatID
	s.i.tgsend = func(str string) error {
		go func() {
			msg := telegram.NewMessage(adminchat, str)
			msg.ParseMode = "markdown"
			_, e := t.Send(msg)
			if e != nil {
				log.Println("Error sending Telegram chat:", e)
			}
		}()
		return nil
	}
	for i := range updates {
		if i.Message == nil {
			continue
		}
		if i.Message.Text == "" {
			continue
		}

		// accept commands from one user
		if i.Message.From.UserName == "aerthx" && i.Message.Chat.ID == 507963905 {
			args := strings.Split(i.Message.Text, " ")
			buf := &bytes.Buffer{}
			switch args[0] {
			case "restart":
				if err := s.Respawn(); err != nil {
					log.Println(err)
					fmt.Fprintf(buf, "error respawning: %v", err)
					s.i.tgsend(buf.String())
				}
			case "reload":
				if err := s.ReloadConfig(); err != nil {
					fmt.Fprintf(buf, "error: %v\n", err)
				} else {
					fmt.Fprintf(buf, "reloaded config\n")
				}
				if err := s.ReloadTemplates(); err != nil {
					fmt.Fprintf(buf, "error: %v\n", err)
				} else {
					fmt.Fprintf(buf, "reloaded templates\n")
				}
				s.i.tgsend(buf.String())
			case "exec":
				if !s.config.Sec.EnableShell {
					buf.WriteString("Shell is disabled in config.")
					s.i.tgsend(buf.String())
					return
				}
				if len(args) < 2 {
					return
				}
				var cmd *exec.Cmd
				if args[1] == "rm" {
					s.i.tgsend("rm disabled")
					return
				}
				if len(args) == 2 {
					cmd = exec.Command(args[1])
				} else {
					cmd = exec.Command(args[1], args[2:]...)
				}
				cmd.Stderr = os.Stderr
				cmd.Stdout = os.Stdout
				cmd.Stdin = nil
				if err := cmd.Run(); err != nil {
					log.Println("exec error:", err)
					return
				}

				s.i.tgsend("started")

			case "stats":
				stats := s.Stats // copied?
				if !stats.t1.IsZero() {
					d := time.Since(s.Stats.t1)
					stats.Uptime = d.Truncate(time.Second).Seconds()
					stats.Average = math.Round(float64(stats.Hits)/stats.Uptime*100) / 100
				}
				json.NewEncoder(buf).Encode(stats)

				s.i.tgsend(fmt.Sprintf(`Stats:

%s

`, buf.String()))

			case "help", "/help":
				msgText := "**Hello**, welcome."
				msg := telegram.NewMessage(i.Message.Chat.ID, msgText)
				msg.ParseMode = "markdown"
				m, err := t.Send(msg)
				if err != nil {
					l.Println("error sending message to telegram:", err)
				}
				_ = m
			}
		}
		//		l.Println(pretty.Sprint(i.Message.From, i.Message.Chat))
		if i.Message.Chat.Title == "" && i.Message.Chat.IsPrivate() {
			i.Message.Chat.Title = "[dm]"
		}
		l.Printf("%s [%s] %s", i.Message.Chat.Title, i.Message.From.UserName, i.Message.Text)
		// end loop
	}

}
