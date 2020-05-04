VERSION ?= $(shell git describe --dirty --tags --abbrev=6 --always)
buildflags ?= -v

buildflags += --ldflags "-X main.Version=$(VERSION)"
bin/webd: *.go */*.go
	mkdir -p bin
	go build $(buildflags) -o $@ .
version.go:
	env VERSION=$(VERSION) go generate -v
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
