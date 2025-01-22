FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/client

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/bin/client /usr/local/bin/
RUN chmod +x /usr/local/bin/client
ENTRYPOINT ["client"]