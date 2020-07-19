package system

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	// for cookies
	"github.com/aerth/webd/config"
	"github.com/aerth/webd/i/captcha"
	"github.com/crewjam/csp"
	"github.com/gorilla/csrf"
)

func (s *System) SetCSPHeader(w http.ResponseWriter) {
	if true {
		return
	}

	u, err := url.Parse(s.config.Meta.SiteURL)
	if err != nil {
		log.Println("Cant set Content-Security-Policy:", err)
		return
	}
	val := csp.Header{
		DefaultSrc: []string{"'self'", u.Hostname()},
		ImgSrc:     []string{"'self'", u.Hostname(), "data:"},

		// UpgradeInsecureRequests: true,

		ScriptSrc: []string{"'self'", u.Hostname()}, // prevents inline js in templates! use static files
		FontSrc:   []string{"'self'", u.Hostname()},
		StyleSrc:  []string{"'self'", u.Hostname()},
	}.String()
	w.Header().Set("Content-Security-Policy", val)
}

const MaxAttempts = 3

func (s *System) serveTemplate(w http.ResponseWriter, r *http.Request, tname string, userinfo *User) {
	//log.Println("executing template:", tname)
	s.SetCSPHeader(w)
	w.Header().Set("Access-Control-Allow-Origin", s.config.Meta.SiteURL)
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	t, ok := s.templates[tname]
	if !ok {
		http.ServeFile(w, r, filepath.Join("www", "public", tname))
		//http.NotFound(w, r)
		return
	}
	if s.config.Meta.LiveTemplate {
		var err error
		t, err = func(tname string) (*template.Template, error) {
			t1 := time.Now()
			t, err = parseTemplateFile(s.config, tname)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse template %q: %v", tname, err)
			}
			log.Printf("Live Parsed %q template in %s", tname, time.Since(t1))
			return t, nil
		}(tname)
		if err != nil {
			// handle error
			log.Println("Error live reloading template:", err)
			return
		}
	}
	var name string
	if userinfo != nil {
		name = userinfo.Name
	}

	var pageTitle = s.config.Meta.SiteName

	if pageTitle != "" {
		pageTitle += " | "
	}

	switch tname {
	case "index.html":
		pageTitle += "Home"
	default:
		pageTitle += strings.Title(strings.Split(tname, ".")[0])
	}

	t.ExecuteTemplate(w, tname, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
		"csrfToken":      csrf.Token(r),
		"userinfo":       userinfo,
		"username":       name,
		"pageTitle":      pageTitle,
		"hits":           s.Stats.Hits,
		"uptime":         time.Since(s.Stats.t1).Truncate(time.Second),
		"sitename":       s.config.Meta.SiteName,
		"copyrightname":  s.config.Meta.CopyrightName,
		"meta":           s.config.Meta.TemplateData,
		"CaptchaID":      captcha.New(),
	})
}

func (s *System) writeCookie(w http.ResponseWriter, value map[string]string) error {
	encoded, err := s.cookies.Encode("cookie-name", value)
	if err == nil {
		cookie := &http.Cookie{
			Name:  "cookie-name",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(w, cookie)
	}
	return err
}

// read cookie
func (s *System) readCookie(r *http.Request) (map[string]string, error) {
	cookie, err := r.Cookie("cookie-name")
	if err != nil {
		if err != http.ErrNoCookie {
			log.Println("error reading cookie from request:", err)
		}
		return nil, err
	}
	value := make(map[string]string)
	err = s.cookies.Decode("cookie-name", cookie.Value, &value)
	if err == nil {
		return value, nil
	}
	return nil, err

}
func (s *System) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", s.config.Meta.SiteURL)
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	log.Println("logging out user!")
	cookieinfo, err := s.readCookie(r)
	if err != nil {
		// create empty cookie
		value := map[string]string{
			"loggedout": "true",
		}
		// re-issue empty cookie
		if err := s.writeCookie(w, value); err != nil {
			log.Println("error writing cookie:", err)
		}
		http.Redirect(w, r, "/login", 500)
		return
	}

	// if cookie was good, we have the authkey. revoke it.
	uid, ok := cookieinfo["user"]
	if ok {
		err = s.authkeyRevoke(uid)
		if err != nil {
			log.Println("error revoking authkey:", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	// re-issue empty cookie
	value := map[string]string{
		"loggedout": "true",
	}
	if err := s.writeCookie(w, value); err != nil {
		log.Println("error writing cookie:", err)
	}

	// redirect to home
	http.Redirect(w, r, "/", http.StatusFound)
	return

}

func (s *System) ErrHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("got error")
	fmt.Fprintf(w, "got an error, sorry.")
}

func (s *System) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// check method
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	// already logged in?
	var loggedIn = false
	cookieinfo, err := s.readCookie(r)
	if err == nil {
		loggedIn = s.authkeyCheck(cookieinfo)
	}
	if loggedIn {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	// display form or process login
	switch r.Method {
	case http.MethodGet:
		s.serveTemplate(w, r, "login.html", nil)
		return
	case http.MethodPost:
		w.Header().Set("Access-Control-Allow-Origin", s.config.Meta.SiteURL)
		w.Header().Set("X-CSRF-Token", csrf.Token(r))
		user := r.FormValue("email")
		pass := r.FormValue("password")
		u, err := s.doLogin(LoginPacket{User: user, Pass: pass})
		if err != nil {
			log.Println("error logging in:", err)
			s.addBadAttempt(r)
			http.Redirect(w, r, "/login?error=Authentication+Failed", http.StatusFound)
			return
		}

		log.Println("got user:", u.String())

		value := map[string]string{
			"user":    user,
			"authkey": u.authkey,
		}
		s.writeCookie(w, value)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
}
func (s *System) DashboardHandler(w http.ResponseWriter, r *http.Request) {
	var loggedIn = false
	cookieinfo, err := s.readCookie(r)
	if err == nil {
		loggedIn = s.authkeyCheck(cookieinfo)
	}
	if !loggedIn {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// get userinfo from db
	var userinfo *User
	if loggedIn {
		userinfo, err = s.getUserByLogin(cookieinfo["user"])
		if err != nil {
			log.Println("error getting userinfo:", err)
			http.Error(w, "bad user", http.StatusForbidden)
			return
		}
	}

	w.Header().Set("Access-Control-Allow-Origin", s.config.Meta.SiteURL)
	w.Header().Set("X-CSRF-Token", csrf.Token(r))

	switch r.Method {
	case http.MethodGet:
		s.serveTemplate(w, r, "dashboard.html", userinfo)
		return
	case http.MethodPost:
		w.Header().Set("Access-Control-Allow-Origin", s.config.Meta.SiteURL)
		w.Header().Set("X-CSRF-Token", csrf.Token(r))
		return
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
}

func (s *System) SignupHandler(w http.ResponseWriter, r *http.Request) {
	// check method
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}

	// already logged in?
	var loggedIn = false
	cookieinfo, err := s.readCookie(r)
	if err == nil {
		loggedIn = s.authkeyCheck(cookieinfo)
	}
	if loggedIn {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// display form or process signup
	switch r.Method {
	case http.MethodGet:
		s.serveTemplate(w, r, "signup.html", nil)
		return
	case http.MethodPost:
		w.Header().Set("Access-Control-Allow-Origin", s.config.Meta.SiteURL)
		w.Header().Set("X-CSRF-Token", csrf.Token(r))
		user := r.FormValue("email")
		pass := r.FormValue("password")
		u, err := s.doSignup(SignupPacket{User: user, Pass: pass})
		if err != nil {
			log.Println("error signing up:", err)
			http.Redirect(w, r, "/signup?error="+err.Error(), http.StatusFound)
			return
		}
		log.Println("got new user:", u)

		value := map[string]string{
			"user":    user,
			"authkey": u.authkey,
		}
		s.writeCookie(w, value)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}

}

// HitCounter http middleware that logs and counts
func (s *System) HitCounter(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(logr(r))
		s.Stats.Hits++
		h.ServeHTTP(w, r)
	})
}
func (s *System) HomeHandler(w http.ResponseWriter, r *http.Request) {
	// extract path
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		// return OK if OPTIONS or HEAD on main page
		if r.Method == http.MethodOptions || r.Method == http.MethodHead {
			// 200
			return
		}

		path = "index.html"
	}

	// only GET on main page
	if r.Method != http.MethodGet {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}

	if _, err := os.Stat(filepath.Join(s.config.Meta.PathTemplates, path)); err == nil {
		s.serveTemplate(w, r, path, nil)
		return
	}
	// 404s
	if path != "index.html" {
		if s.config.Sec.ServePublic {
			s.StaticHandler(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	w.Header().Set("X-CSRF-Token", csrf.Token(r))

	// check if user is authenticated
	var loggedIn = false
	cookieinfo, err := s.readCookie(r)
	if err == nil {
		loggedIn = s.authkeyCheck(cookieinfo)
	}

	// get userinfo if logged in
	var userinfo *User
	if loggedIn {
		userinfo, err = s.getUserByLogin(cookieinfo["user"])
		if err != nil {
			log.Println("error getting userinfo:", err)
			http.Error(w, "bad user", http.StatusForbidden)
			return
		}
	}
	log.Println("serving template:", path)
	s.serveTemplate(w, r, path, userinfo)
	return
}

func (s *System) StaticHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions || r.Method == http.MethodHead {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Expires", time.Now().Add(time.Hour*24).UTC().Truncate(time.Second).Format(http.TimeFormat))
	filename := filepath.Join("www", "public", r.URL.Path)
	if strings.HasSuffix(filename, ".css") {
		w.Header().Set("Content-Type", "text/css")
	}
	if strings.HasSuffix(filename, ".js") {
		w.Header().Set("Content-Type", "text/javascript")
	}
	http.ServeFile(w, r, filename)
	return
}

// ez http log
func logr(r *http.Request) string {
	ipaddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println(err)
		ipaddr = r.RemoteAddr
	}
	ipaddr += " "
	ipaddr += r.Header.Get("X-Forwarded-For")

	return fmt.Sprintf("(%s) %s %s %.50q %q %s", r.URL.RawPath, r.Host, r.Method, r.UserAgent(), ipaddr, r.URL.Path)
}

// authkeyRevoke sets a random sessionkey, revoking any cookies in the wild
func (s *System) authkeyRevoke(uid string) error {
	authkeyb := make([]byte, 32)
	rand.Read(authkeyb)
	return s.boltdbUpdate("authkeys", uid, authkeyb)
}

// authkeyCheck returns true if user's cookie sessionkey matches the single valid sessionkey in database
func (s *System) authkeyCheck(cookieinfo map[string]string) bool {
	authedKey, maybeLoggedIn1 := cookieinfo["authkey"]
	authedUser, maybeLoggedIn2 := cookieinfo["user"]
	if !maybeLoggedIn1 || !maybeLoggedIn2 {
		return false
	}
	authkeyb, err := s.boltdbFetch("authkeys", authedUser)
	if err != nil || len(authkeyb) == 0 {
		log.Println("attempted break-in", err)
		return false
	}
	return authedKey == fmt.Sprintf("%02x", authkeyb)
}

// addBadAttempt
func (s *System) addBadAttempt(r *http.Request) {
	if s.greylist == nil {
		log.Println("WARN: no greylist instance to add guy attempts")
		return
	}

	ipaddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println(err)
		ipaddr = r.RemoteAddr
	}
	ipaddr += " "
	ipaddr += r.Header.Get("X-Forwarded-For")

	// slows connection, but only for bad guys
	s.badguylock.Lock()
	counter := s.badguys[ipaddr]
	if counter == nil {
		counter = new(uint32)
		s.badguys[ipaddr] = counter
	}
	s.badguylock.Unlock()

	*counter++
	// this counter doesn't reset, so after getting banned+unbanned only one attempt will re-ban
	// TODO: admin interface to add/remove/reset counters
	if *counter >= MaxAttempts {
		log.Println("adding to blacklist:", ipaddr)
		s.greylist.Blacklist(r)
	}
}

func ReverseProxyHandler(config config.Config, path, dest string) (http.Handler, error) {
	if config.Meta.DevelopmentMode {
		log.Printf("adding reverse proxy: %s=>%s", path, dest)
	}
	target, err := url.Parse(dest)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse reverse proxy destination: %v", err)
	}
	prx := httputil.NewSingleHostReverseProxy(target)
	// custom director to remove cookies, remove path prefix
	prx.Director = func(req *http.Request) {
		target := target
		// clear cookies
		req.Header.Del("Cookie")
		req.Host = target.Host
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = strings.TrimPrefix(req.URL.Path, strings.TrimSuffix(path, "/"))
		if target.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}

		// log request
		log.Printf("relaying: %s://%s%s %s %s", req.URL.Scheme, req.Host, req.URL.Path, req.URL.Query().Encode(), logr(req))
	}
	prx.ErrorLog = log.New(os.Stderr, "ReverseProxy: ", log.LstdFlags)
	return prx, nil
}
