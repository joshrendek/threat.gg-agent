SHELL=/bin/bash
BUILD_NUMBER=${GITHUB_RUN_ID}
BINARY=honeypot

.PHONY: proto
proto:
	protoc -I $(HOME)/dev/threat.gg --go-grpc_out=proto/ --go-grpc_opt=paths=source_relative --go_out=proto/ --go_opt=paths=source_relative ~/dev/threat.gg/honeypot.proto

all: build

build:
	@echo "*****"
	@echo ${BUILD_NUMBER}
	@echo "*****"
	mkdir -p dist
	GOOS=linux CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s' \
	  -ldflags "-X main.Version=`date -u +%Y%m%d`.${BUILD_NUMBER}" -o dist/${BINARY}
	GOOS=linux CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s' \
	  -ldflags "-X main.Version=`date -u +%Y%m%d`.${BUILD_NUMBER}" -o dist/${BINARY}_x86_64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s' \
	  -ldflags "-X main.Version=`date -u +%Y%m%d`.${BUILD_NUMBER}" -o dist/${BINARY}_arm64
	GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s' \
	  -ldflags "-X main.Version=`date -u +%Y%m%d`.${BUILD_NUMBER}" -o dist/${BINARY}_armv7l
	GOOS=linux GOARCH=arm CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s' \
	  -ldflags "-X main.Version=`date -u +%Y%m%d`.${BUILD_NUMBER}" -o dist/${BINARY}_armv6l
	cp dist/${BINARY}_arm64 dist/${BINARY}_aarch64
