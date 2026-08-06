FROM golang:1.22.12-bookworm@sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253

ENV GOPROXY=off \
    GOSUMDB=off \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    CGO_ENABLED=0

WORKDIR /app
COPY app/ /app/

RUN make build

CMD ["/bin/bash"]
