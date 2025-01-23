VERSION ?= v0.0.2
REGISTRY ?= fengyu225
SERVER_NAME ?= spiffe-demo-server
CLIENT_NAME ?= spiffe-demo-client
IMAGE_TAG ?= $(VERSION)

.PHONY: init
init:
	@echo "Initializing Go modules..."
	@if [ ! -f certificate/go.mod ]; then \
		cd certificate && go mod init certificate; \
	fi
	cd certificate && go get github.com/fsnotify/fsnotify && go mod tidy
	@if [ ! -f server/go.mod ]; then \
		cd server && go mod init server; \
	fi
	cd server && go mod edit -replace certificate=../certificate && go mod tidy
	@if [ ! -f client/go.mod ]; then \
		cd client && go mod init client; \
	fi
	cd client && go mod edit -replace certificate=../certificate && go mod tidy

.PHONY: build
build: init build-server build-client

.PHONY: build-server
build-server:
	cd server && CGO_ENABLED=0 go build -o bin/server

.PHONY: build-client
build-client:
	cd client && CGO_ENABLED=0 go build -o bin/client

.PHONY: docker-build
docker-build: docker-build-server docker-build-client

.PHONY: docker-build-server
docker-build-server:
	docker build --platform linux/amd64 -t $(REGISTRY)/$(SERVER_NAME):$(IMAGE_TAG) -f server/Dockerfile .

.PHONY: docker-build-client
docker-build-client:
	docker build --platform linux/amd64 -t $(REGISTRY)/$(CLIENT_NAME):$(IMAGE_TAG) -f client/Dockerfile .

.PHONY: docker-push
docker-push: docker-push-server docker-push-client

.PHONY: docker-push-server
docker-push-server:
	docker push $(REGISTRY)/$(SERVER_NAME):$(IMAGE_TAG)

.PHONY: docker-push-client
docker-push-client:
	docker push $(REGISTRY)/$(CLIENT_NAME):$(IMAGE_TAG)

.PHONY: clean
clean:
	rm -f server/bin/server
	rm -f client/bin/client

.PHONY: clean-deps
clean-deps:
	rm -f */go.sum
	rm -f */go.mod