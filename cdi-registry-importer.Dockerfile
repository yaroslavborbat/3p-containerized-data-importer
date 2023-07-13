FROM golang:1.20-bookworm AS builder
WORKDIR /go/src/github.com/deckhouse/3p-containerized-data-importer
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
    libnbd-dev
COPY . ./
RUN go build ./cmd/cdi-registry-importer && \
    chmod +x cdi-registry-importer

FROM debian:bookworm-slim
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
    ca-certificates \
    libnbd0 \
    qemu-utils \
    file && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /go/src/github.com/deckhouse/3p-containerized-data-importer/cdi-registry-importer /usr/local/bin/cdi-registry-importer
CMD ["/usr/local/bin/cdi-registry-importer"]