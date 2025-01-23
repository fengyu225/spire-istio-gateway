FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY certificate /app/certificate/
COPY client /app/client/

WORKDIR /app/client
RUN go mod download
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -o bin/client

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/client/bin/client /usr/local/bin/
RUN chmod +x /usr/local/bin/client
ENTRYPOINT ["client"]