package system

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aerth/webd/i/captcha"
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

func getip(r *http.Request) string {
	return r.RemoteAddr
}
func (s *System) HandleForm(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	default:
		serveJsonError(w, "not implemented", 500)
		return
	case "/contact", "/contact.json":
		if err := r.ParseForm(); err != nil {
			log.Printf("error parsing form: %v", err)
			serveJsonError(w, "form parse error", 500)
			return
		}
		if !captcha.VerifyString(r.FormValue("captchaID"), r.FormValue("captchaSol")) {
			log.Printf("bad captcha.", r.FormValue("captchaID"), r.FormValue("captchaSol"))
			serveJsonError(w, "bad captcha. are you human? go back and refresh the captcha image", 500)
			return
		}
		str := &strings.Builder{}
		fmt.Fprintf(str, "```\n")
		fmt.Fprintf(str, "time: %s\n", time.Now().UTC().Truncate(time.Second))
		fmt.Fprintf(str, "ip: %s\n", getip(r))
		fmt.Fprintf(str, "referer: %s\n", r.Referer())
		for k, v := range r.Form {
			if k == "_csrf" || k == "submit" || k == "captchaID" || k == "captchaSol" {
				continue
			}
			fmt.Fprintf(str, "%s: %s\n", k, v)
		}
		fmt.Fprintf(str, "```\n")
		s.i.tgsend(str.String())
		if r.URL.Path == "/contact" { // just give 200 for jsonrpc
			http.Redirect(w, r, "/", http.StatusFound)
		}
		return
	}
}
