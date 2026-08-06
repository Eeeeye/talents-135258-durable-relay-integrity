FROM golang:1.22-bookworm

ENV GOPROXY=off \
    GOSUMDB=off \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    CGO_ENABLED=0

WORKDIR /app
COPY app/ /app/

RUN go test -buildvcs=false ./... \
    && make build

CMD ["/bin/bash"]
