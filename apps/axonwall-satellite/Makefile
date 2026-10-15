.PHONY: all clean build-linux-amd64 build-linux-arm64 build-linux-mips

VERSION := 0.5.2
LDFLAGS := -s -w -X main.Version=$(VERSION)

all: clean build-linux-amd64 build-linux-arm64 build-linux-mips

clean:
	rm -rf bin/

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/axonwall-satellite-amd64 main.go

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/axonwall-satellite-arm64 main.go

# Compile for typical OpenWrt MIPS routers (32-bit, soft-float/hard-float depending on GOMIPS)
build-linux-mips:
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags="$(LDFLAGS)" -o bin/axonwall-satellite-mipsle main.go
