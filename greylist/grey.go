// Copyright (c) 2020 aerth <aerth@riseup.net>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// package greylist implements a basic whitelisting/blacklisting http.Handler
//
// It reads 2 files (whitelist file, blacklist file) and has option to
// periodically refresh the lists. It also provides an additional Blacklist(ip)
// method for temporary bans.
package greylist

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const DefaultTemporaryBlacklistTime = time.Hour

// List is a greylist instance
type List struct {
	whitelistFilename, blacklistFilename string
	underlyingHandler                    http.Handler
	whitelist, blacklist                 map[string]struct{}
	cache                                <-chan time.Time
	lastTime                             time.Time
	mu                                   sync.RWMutex
	temporaryBlacklist                   map[string]time.Time
	allMethods                           bool
	refreshRate                          time.Duration
	temporaryBlacklistTime               time.Duration
}

// New accepts whitelist filename, blacklist filename, and a refreshrate duration
// If the files don't exist or are empty, they are not used, and read errors will not be reported.
// refreshRate can be 0, in which case no automatic refreshing is done. (see RefreshLists())
//
// After calling New(), a program can use l.Protect() to wrap a http.Handler.
//
// By default, only non-GET requests are protected.
// If your program demands, use l.SetAllMethods(true)
//
// By default, temporary bans are one hour.
// To change this, call l.SetTemporaryBlacklistTime(time.Duration)
func New(whitelistFilename, blacklistFilename string, refreshRate time.Duration) *List {

	var tick <-chan time.Time
	if refreshRate > 0 {
		tick = time.Tick(refreshRate)
	}

	b, err := ioutil.ReadFile(whitelistFilename)
	if err == nil && len(b) > 2 {
		if !(b[len(b)-1] == '\n' && b[len(b)-2] == '\n') {
			log.Println("Warning: whitelist file does not end in newline")
		}
	}
	b, err = ioutil.ReadFile(blacklistFilename)
	if err == nil && len(b) > 2 {
		if !(b[len(b)-1] == '\n' && b[len(b)-2] == '\n') {
			log.Println("Warning: blacklist file does not end in newline")
		}
	}

	l := &List{
		whitelistFilename:      whitelistFilename,
		blacklistFilename:      blacklistFilename,
		cache:                  tick,
		whitelist:              make(map[string]struct{}),
		blacklist:              make(map[string]struct{}),
		temporaryBlacklist:     make(map[string]time.Time),
		temporaryBlacklistTime: DefaultTemporaryBlacklistTime,
		refreshRate:            refreshRate,
	}
	go l.RefreshLists()
	return l
}

// Protect a http.Handler
//
// http.ListenAndServe(":8080", glist.Protect(myHandler))
//
func (l *List) Protect(h http.Handler) http.Handler {
	l.underlyingHandler = h
	return l
}

// SetAllMethods blocks all requests from blacklisted IPs. Use with caution as it currently slows requests for everyone
func (l *List) SetAllMethods(b bool) {
	l.allMethods = b
}

// SetTemporaryBlacklistTime sets the duration that offenders will be blacklisted for
func (l *List) SetTemporaryBlacklistTime(d time.Duration) {
	l.temporaryBlacklistTime = d
}

// Blacklist adds a temporary ban to an ip address
func (l *List) Blacklist(r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println(err)
		ip = r.RemoteAddr
	}
	ip += " "
	ip += r.Header.Get("X-Forwarded-For")

	l.mu.Lock()
	l.temporaryBlacklist[ip] = time.Now().Add(l.temporaryBlacklistTime)
	l.mu.Unlock()
	log.Printf("greylist: blacklisting for %s: %q", l.temporaryBlacklistTime, ip)
}

// ServeHTTP implements http.Handler interface
func (l *List) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// quick short circuit for GET requests
	if !l.allMethods && r.Method == http.MethodGet {
		l.underlyingHandler.ServeHTTP(w, r)
		return
	}

	// check cache time, refresh if necessary
	if l.refreshRate > 0 {
		select {
		case <-l.cache:
			go l.RefreshLists()
		default:
		}
	}

	// get IP ("ok behind reverse proxy with x-forwarded-for header")
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println(err)
		ip = r.RemoteAddr
	}
	ip += " "
	ip += r.Header.Get("X-Forwarded-For")

	// locked for map reads, unlock asap (before setting headers or writing to conn)
	l.mu.RLock()
	if _, ok := l.whitelist[ip]; ok {
		l.mu.RUnlock()
		log.Printf("greylist: allowing whitelisted ip %q", ip)
		l.underlyingHandler.ServeHTTP(w, r)
		return
	}
	if _, ok := l.blacklist[ip]; ok {
		l.mu.RUnlock()
		log.Printf("greylist: blocking blacklisted ip %q", ip)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	t, temporarilyBanned := l.temporaryBlacklist[ip]
	l.mu.RUnlock()
	if temporarilyBanned {
		if t.After(time.Now()) {
			log.Printf("greylist: blocking (temp) blacklisted ip %q (until %s)", ip, time.Until(t))
			http.Error(w, fmt.Sprintf("You have been blocked for %s", time.Until(t)), http.StatusForbidden)
			return
		}
		log.Printf("greylist: removing temporary blacklist ip %q", ip)
		delete(l.temporaryBlacklist, ip)
	}

	// serve it
	l.underlyingHandler.ServeHTTP(w, r)
}

// RefreshLists reads the whitelist and blacklist files and sets new maps (removed ips will not be in new map)
// Errors are ignored, in case the file doesn't exist or is not readable.
//
// Note: Files must end in an empty newline, and windows newlines are not supported. (Only checks '\n\n')
func (l *List) RefreshLists() {
	t1 := time.Now()
	whitelist := make([]string, 1024)
	blacklist := make([]string, 1024)
	l1, l2 := 0, 0
	f, err := os.Open(l.whitelistFilename)
	if err == nil {
		info, err := f.Stat()
		if err == nil {
			if info.ModTime().After(l.lastTime) {
				// do refresh
				count := 0
				scanner := bufio.NewScanner(f)
				// scan lines (require newline at end of file)
				for scanner.Scan() {
					if count > len(whitelist)-1 {
						whitelist = append(whitelist, make([]string, 1024)...)
					}
					ip := scanner.Text()
					if ip != "" {
						whitelist[count] = ip
						l1 = count
						count++
					}
				}

				if err := scanner.Err(); err != nil {
					log.Println("error scanning whitelist:", err)
				}

				l.mu.Lock()
				l.whitelist = map[string]struct{}{}
				for _, v := range whitelist[:count] {
					l.whitelist[v] = struct{}{}
				}
				l.mu.Unlock()

			}
		}
	}
	f.Close()

	f, err = os.Open(l.blacklistFilename)
	if err == nil {
		info, err := f.Stat()
		if err == nil {
			if info.ModTime().After(l.lastTime) {
				// do refresh

				count := 0
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					if count > len(blacklist)-1 {
						blacklist = append(blacklist, make([]string, 1024)...)
					}
					ip := scanner.Text()
					if ip != "" {
						blacklist[count] = ip
						l2 = count
						count++
					}
				}

				if err := scanner.Err(); err != nil {
					log.Println("error scanning blacklist:", err)
				}

				l.mu.Lock()
				l.blacklist = map[string]struct{}{}
				for _, v := range blacklist[:count] {
					l.blacklist[v] = struct{}{}
				}
				l.mu.Unlock()
			}
		}
	}
	f.Close()

	if l.refreshRate > 0 {
		var str string
		str = fmt.Sprintf(" next refresh is in %s.", l.refreshRate)
		log.Printf("greylist: refreshed lists from file in %s, whitelisted %d, blacklisted %d.%s", time.Since(t1), l1, l2, str)
	}
	/* // debug
	for i := range l.whitelist {
			log.Printf("whitelist: %q", i)
		}
		for i := range l.blacklist {
			log.Printf("blacklist: %q", i)
		}
	*/
	l.lastTime = time.Now()
}
