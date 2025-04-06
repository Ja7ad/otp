# Build stage
FROM golang:1.24-alpine AS builder
RUN apk --no-cache add make
WORKDIR /app
COPY . .
RUN make build-otp-api

FROM alpine:latest
COPY --from=builder /app/build/otp /usr/bin/otp
EXPOSE 8080
ENTRYPOINT ["/usr/bin/otp", "-serve", ":8080"]
