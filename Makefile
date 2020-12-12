
.PHONY: test test2 docker protobuf

test: protobuf
	go test --race ./...

testv: protobuf
	go test --race -v -count=1 ./...

docker:
	docker build -t p2putil:latest .

protobuf:
	cd ./s/noiseswarm && ./build.sh	

