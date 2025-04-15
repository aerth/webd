module github.com/aerth/webd

// +heroku goVersion go1.14
go 1.23.0

toolchain go1.24.2

require (
	github.com/aerth/diamond v0.4.9
	github.com/crewjam/csp v0.0.2
	github.com/gorilla/csrf v1.7.3
	github.com/gorilla/securecookie v1.1.2
	github.com/plutov/paypal/v3 v3.1.0
	github.com/technoweenie/multipartstreamer v1.0.1
	gitlab.com/aerth/greylist v0.0.2
	go.etcd.io/bbolt v1.4.0
	golang.org/x/crypto v0.37.0
)

require (
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
)
