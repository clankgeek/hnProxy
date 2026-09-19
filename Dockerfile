FROM golang:1.27-alpine AS builder
RUN apk add make
WORKDIR /app
COPY . .
RUN make build
