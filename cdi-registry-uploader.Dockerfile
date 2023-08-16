FROM golang:1.20-bookworm AS builder
WORKDIR /go/src/github.com/deckhouse/3p-containerized-data-uploader
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
    libnbd-dev
COPY . ./
RUN go build ./cmd/cdi-registry-uploader && \
    chmod +x cdi-registry-uploader

FROM debian:bookworm-slim
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
    ca-certificates \
    libnbd0 \
    qemu-utils \
    file && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /go/src/github.com/deckhouse/3p-containerized-data-uploader/cdi-registry-uploader /usr/local/bin/cdi-registry-uploader
CMD ["/usr/local/bin/cdi-registry-uploader"]