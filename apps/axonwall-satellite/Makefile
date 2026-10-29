.PHONY: all clean build-linux-amd64 build-linux-amd64-v3 build-linux-arm64 build-linux-mips

VERSION := 0.11.33
LDFLAGS := -s -w -X main.Version=$(VERSION)

all: clean build-linux-amd64 build-linux-amd64-v3 build-linux-arm64 build-linux-mips

clean:
	rm -rf bin/

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/axonwall-satellite-amd64 main.go

# Hardware-tuned x86_64-v3 (AVX2/BMI2/FMA) binary for manufactured Intel N100/N305 & Xeon/EPYC Edge NGFWs
build-linux-amd64-v3:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/axonwall-edge-amd64-v3 main.go

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/axonwall-satellite-arm64 main.go

# Compile for typical OpenWrt MIPS routers (32-bit, soft-float/hard-float depending on GOMIPS)
build-linux-mips:
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags="$(LDFLAGS)" -o bin/axonwall-satellite-mipsle main.go
