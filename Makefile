all: build

ENVVAR = GOOS=linux GOARCH=amd64
TAG = v0.1.1
APP_NAME = calico-accountant

clean:
	rm -f $(APP_NAME)

fmt:
	find . -path ./vendor -prune -o -name '*.go' -print | xargs -L 1 -I % gofmt -s -w %

build: clean fmt
	$(ENVVAR) CGO_ENABLED=0 go build -o $(APP_NAME)

test-unit: clean fmt build
	CGO_ENABLED=0 go test -v -cover ./...

# Make the container using docker multi-stage build process
# So you don't necessarily have to install golang to make the container
container:
	docker build -f Dockerfile -t monzo/$(APP_NAME):$(TAG) .

.PHONY: all clean fmt build container
