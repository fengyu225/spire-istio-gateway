FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY certificate /app/certificate/
COPY server /app/server/

WORKDIR /app/server
RUN go mod download
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o bin/server

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/server/bin/server /usr/local/bin/
RUN chmod +x /usr/local/bin/server
ENTRYPOINT ["server"]