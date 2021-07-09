
.PHONY: test test2 docker

test:
	go test --race ./...

testv:
	go test --race -v -count=1 ./...

docker:
	docker build -t p2putil:latest .

