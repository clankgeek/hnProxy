FROM golang:1.25-alpine AS builder
RUN apk add make
WORKDIR /app
COPY . .
RUN make build
