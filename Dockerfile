FROM golang:1.26-alpine AS builder
RUN apk add make
WORKDIR /app
COPY . .
RUN make build
