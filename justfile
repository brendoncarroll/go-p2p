
test:
	go test --race ./...

testv:
	go test --race -v -count=1 ./...

bench:
	go test -v -bench=. -run=Benchmark ./...

docker:
	docker build -t p2putil:latest .

protobuf:
	cd ./p/p2pke && ./build.sh

