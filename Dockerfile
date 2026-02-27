# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder
WORKDIR /app

# Copy all your code into the container
COPY . .

# Force Docker to create fresh dependency files in the cloud
RUN rm -f go.mod go.sum
RUN go mod init github.com/Uloga1/pre-seederr
RUN go mod tidy

# Compile the application
RUN go build -o pre-seederr .

# Stage 2: Create the final lightweight image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/pre-seederr .
COPY templates/ templates/

EXPOSE 5000
CMD ["./pre-seederr"]