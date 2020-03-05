
.PHONY: test docker

test:
	go test ./...

docker:
	docker build -t p2putil:latest .