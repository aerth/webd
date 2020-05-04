# greylist

package greylist implements a basic whitelisting/blacklisting http.Handler

Greylist is a standalone package that can be used by any go web server.
It wraps an http.Handler and protects non-GET requests using 2 text files and an additional in-memory map.

It never writes to the list files. Your go program can do that on its own, and then call g.ReloadLists() manually. If the lists change often, you can set automatic reloads using the third parameter of `greylist.New()` when making your `*List`

It reads 2 files (whitelist file, blacklist file) and has option to periodically refresh the lists. It also provides an additional Blacklist(ip) method for temporary bans.

Under the hood, it uses a `sync.RWMutex` and 3 `map[string]struct{}`s to keep track of whitelisted and blacklisted and temporary-blacklisted IP addresses. GET requests are not checked.

[API Documentation](https://pkg.go.dev/github.com/aerth/webd@v0.0.2/greylist?tab=doc)
