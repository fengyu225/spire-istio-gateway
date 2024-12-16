VERSION ?= 0.1.1
REGISTRY ?= fengyu225
IMAGE_NAME ?= spiffe-csi-driver
IMAGE_TAG ?= $(VERSION)

.PHONY: build
build:
	CGO_ENABLED=0 go build -o bin/spiffe-csi-driver ./cmd/spiffe-csi-driver

.PHONY: docker-build
docker-build:
	docker build --platform linux/amd64 -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: docker-push
docker-push:
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
