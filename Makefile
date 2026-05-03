.PHONY: all build test vet clean install update-probes

BINARY := gomap
LDFLAGS := -s -w

all: build

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

install:
	go install -trimpath -ldflags="$(LDFLAGS)" .

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) coverage.out

# Refresh the embedded nmap probe database from upstream.
update-probes:
	curl -sSL https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes \
	     -o pkg/nmapprobe/nmap-service-probes
	@echo "Probe database refreshed. Don't forget to commit and rebuild."
