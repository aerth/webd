package system

import (
	"fmt"
	"log"
	"os"
)

func (s *System) auditlog(format string, i ...interface{}) {
	if s.files.AuditLog == nil {
		f, err := os.OpenFile("/tmp/webd-audit.log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			log.Println("Error opening audit log:", err)
			log.Printf("WARNING: CANT OPEN AUDIT LOG!!!"+format, i...)
			return
		}
		s.files.AuditLog = f
	}
	fmt.Fprintf(s.files.AuditLog, format, i...)
}
