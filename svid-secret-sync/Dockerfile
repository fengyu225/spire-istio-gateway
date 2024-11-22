FROM golang:1.21 as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
# Explicitly set the architecture to amd64
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o svid-secret-sync .

FROM alpine:3.18
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/svid-secret-sync /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/svid-secret-sync"]