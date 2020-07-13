package system

import (
	"fmt"
	"log"
	"os"

	"github.com/aerth/webd/i/telegram"
)

func (s *System) auditlog(format string, i ...interface{}) {
	str := fmt.Sprintf(format, i...)

	// log to file
	if s.files.AuditLog == nil {
		f, err := os.OpenFile("/tmp/webd-audit.log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			log.Println("Error opening audit log:", err)
			log.Printf("WARNING: CANT OPEN AUDIT LOG!!!", str)
		} else {
			s.files.AuditLog = f
		}
	}
	if s.files.AuditLog != nil {
		fmt.Fprintf(s.files.AuditLog, format+"\n", i...)
	}
	if s.config.Telegram.AuditChatID != 0 {
		// log to telegram channel
		msg := telegram.NewMessage(s.config.Telegram.AuditChatID, "[audit]\n\n"+str)
		msg.ParseMode = "markdown"
		_, e := s.i.tg.T.Send(msg)
		if e != nil {
			log.Println("Error sending Telegram chat:", e)
		}
	}
}
