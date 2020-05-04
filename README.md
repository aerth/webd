stupid web app

# Features

  * Easy to add new features?
  * Signup, Login, Logout
  * Members-only dashboard (currently open registration)
  * Hit Counter
  * Brute-force protection (via temporary blacklisting)
  * Encrypted Cookies (gorilla/securecookie)
  * Fast, Lightweight
  * CSRF protection (gorilla/csrf)
  * Anti-frame protection via Content-Security-Policy
  * Persistent sessions across reboots (BoltDB)
  * Templates! ([docs](https://golang.org/pkg/text/template/))
  * Reload templates from file by sending USR2 signal (`pkill -usr2 webd`)
  * Reload config from file by sending USR1 signal (`pkill -usr1 webd`)

# Config (config.json)

Variables exposed in templates

SiteURL is used for content-security-policy headers

`templatedata` used exclusively in templates

```
  "Meta": {
    "siteurl": "http://127.0.0.1:8080",
    "sitename": "Test Application",
    "copyright-name": "My Company, Inc",
    "templatedata": {
      "arbitrary-variable-name": "value",
      "var2": "string-value",
      "varNum": 123,
      "varNested": {
        "nest": 321
      }
    }
  },
```

Security variables that should be randomized, cookie-name replaced

```
  "Security": {
    "cookie-name": "cookie-name",
    "csrf-key": "32-byte-long-auth-key",
    "hash-key": "755d813685f17a1d3a74f984b5111840",
    "block-key": "caa7040d2f00aaa548d5bab3aaa72100",
```

Whitelist and Blacklist are file paths to read.
Whitelisted IPs will never be banned, Blacklisted IPs won't be able to do POST requests. After 3 attempts, users are temporarily banned.

If ServePublic is `true`, all files in ./www/public are served.
They are routed after normal pages, so file names can't collide with templated paths (such as "/login" or "/dashboard")

```
    "whitelist": "whitelist.txt",
    "blacklist": "blacklist.txt",
    "servepublic": false
  },
```

### Using encrypted config.json

1. encrypt it with pgp or age
```
age -p config.json > config.json.enc
```

2. decrypt and pipe into webd
```
age -d config.json.enc | webd -conf -
```

### Using Reverse Proxies

In the config.json, /bin/xxx will fetch `https://httpbin.org/xxx`
and /usr/bin/xxx will also fetch `https://httpbin.org/xxx`

Easy to change in config.json, to serve other applications under subdirectories.

Cookies are removed from the fetch.

```
  "ReverseProxy": {
    "/bin/": "https://httpbin.org",
    "/usr/bin/": "https://httpbin.org"
  },
```
