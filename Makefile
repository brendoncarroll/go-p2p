
.PHONY: test docker

test:
	go test --race ./...

docker:
	docker build -t p2putil:latest .
