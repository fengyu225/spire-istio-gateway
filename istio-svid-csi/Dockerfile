FROM golang:1.21-alpine AS builder

RUN apk add --no-cache gcc musl-dev fuse-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY main.go ./
RUN CGO_ENABLED=1 GOOS=linux go build -o svid-csi-driver main.go

FROM alpine:3.18
RUN apk add --no-cache fuse
COPY --from=builder /build/svid-csi-driver /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/svid-csi-driver"]