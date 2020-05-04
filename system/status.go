package system

import (
	"encoding/json"
	"net/http"
	"time"
)

func (s *System) StatusHandler(w http.ResponseWriter, r *http.Request) {
	s.Stats.Hits++
	stats := s.Stats // copied?
	if !stats.t1.IsZero() {
		d := time.Since(s.Stats.t1)
		stats.Uptime = d.Truncate(time.Second).Seconds()
		stats.Average = float64(stats.Hits) / d.Seconds()
	}
	json.NewEncoder(w).Encode(stats)
}
