BINARY_NAME=scc-analyzer

.PHONY: build
build:
	GOARCH=amd64 GOOS=linux go build -o ./build/${BINARY_NAME}-linux main.go

.PHONY: clean
clean:
	rm -rf build