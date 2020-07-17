VERSION ?= $(shell git describe --dirty --tags --abbrev=6 --always)
buildflags ?= -v

buildflags += --ldflags "-X main.Version=$(VERSION)"
bin/webd: VERSION *.go */*.go
	mkdir -p bin
	go build $(buildflags) -o $@ .
version.go:
	env VERSION=$(VERSION) go generate -v
VERSION:
	git tag | tail -n 1 > VERSION
run: www/public bin/webd
	./bin/webd -dev
www/public:
	cd www && unzip ../webassets.zip 
clean:
	rm -rf bin
dist-clean: clean
	rm -f *.log *.txt
.PHONY += clean
.PHONY += dist-clean

webassets.zip: www/public
	cd www && zip -r ../webassets.zip public

reload:
	pkill -e -usr1 webd && pkill -e -usr2 webd && echo reloaded
test:
	go test -v ./... && echo Test Passed
