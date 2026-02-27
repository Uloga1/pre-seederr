# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o pre-seederr .

# Stage 2: Create the final image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/pre-seederr .
COPY templates/ templates/
EXPOSE 5000
CMD ["./pre-seederr"]