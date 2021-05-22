APP?=crypto-token

.PHONY: build
## build: builds the application
build: clean
	@echo "Building..."
	@go build -o ${APP} cmd/*.go

.PHONY: clean
## clean: removes the binary
clean:
	@echo "Cleaning"
	@rm -rf ${APP}

.PHONY: test
## test: runs go test with default values
test:
	go test -v -count=1 -race -cover ./...

.PHONY: bench
## bench: runs benchmarks
bench:
	go test -v -count=1 -bench=. ./... -run NONE

## benchmem: runs processing and memory benchmarks
benchmem:
	go test -v -count=1 -bench=. ./... -benchmem -run NONE

.PHONY: help
## help: prints this help message
help:
	@echo "Usage:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | sort | column -t -s ':' |  sed -e 's/^/ /'

