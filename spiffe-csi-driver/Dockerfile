FROM golang:1.22 as builder

WORKDIR /workspace
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o spiffe-csi-driver ./cmd/spiffe-csi-driver

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/spiffe-csi-driver .
USER root:root

ENTRYPOINT ["/spiffe-csi-driver"]