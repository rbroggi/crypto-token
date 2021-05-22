FROM golang:1.14

WORKDIR /go/src/app
COPY . .

# Run unit-tests
RUN make test

# Run benchmark
RUN make bench

# Build product
RUN make build

ENTRYPOINT [ "/go/src/app/crypto-token" ]
