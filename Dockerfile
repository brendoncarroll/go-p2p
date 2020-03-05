FROM golang:1.13 as go_builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go install -v ./cmd/p2putil

FROM alpine:latest
WORKDIR /app
COPY --from=go_builder /go/bin/p2putil .
EXPOSE 8000
ENTRYPOINT ["./p2putil"]
