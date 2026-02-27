# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder
WORKDIR /app

# Install build essentials
RUN apk add --no-cache git

# Copy everything
COPY . .

# Force absolute fresh dependency generation
RUN rm -f go.mod go.sum
RUN go mod init github.com/Uloga1/pre-seederr
RUN go mod tidy
RUN go build -o pre-seederr .

# Stage 2: Create the final lightweight image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/pre-seederr .
COPY templates/ templates/

EXPOSE 5000
CMD ["./pre-seederr"]