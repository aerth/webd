package system

import (
	"fmt"
	"net/http"
)

func (s *System) ContactHandler(w http.ResponseWriter, r *http.Request) {
	s.Stats.Hits++
	fmt.Fprintf(w, "Contact Form...\n")
}
