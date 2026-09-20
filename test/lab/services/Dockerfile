# Built from the repo root so it can compile the module.
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /labsvc ./test/lab/services

FROM alpine:3.20
RUN adduser -D -u 10001 lab && mkdir -p /data && chown lab /data
USER lab
COPY --from=build /labsvc /labsvc
ENTRYPOINT ["/labsvc"]
