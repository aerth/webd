package system

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *System) ApiHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("api request:", logr(r))
	serveJsonError(w, "not implemented", 500)
	return
}

type JSONError struct {
	Error string `json:"error"`
}

func serveJsonError(w http.ResponseWriter, e string, code int) {
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(JSONError{e}); err != nil {
		log.Println(err)
	}
}
