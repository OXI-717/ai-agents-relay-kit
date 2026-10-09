.PHONY: test build vet
test:
	go test ./...
vet:
	go vet ./...
build:
	go build -o bin/vpn ./cmd/vpn
