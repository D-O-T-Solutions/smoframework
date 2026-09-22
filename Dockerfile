# Multi-stage Dockerfile for smo-node
# Build stage: Ubuntu 22.04 with build dependencies
# Runtime stage: distroless (gcr.io/distroless/cc) with smo-node binary

# =========================================================================
# BUILD STAGE
# =========================================================================
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    ca-certificates \
    libssl-dev \
    libfmt-dev \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /src

# Copy source code
COPY . /src/smoframework

# Build smo-node (Release, with PQC)
RUN mkdir -p /src/smoframework/build && \
    cmake -S /src/smoframework -B /src/smoframework/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DWITH_PQC=ON \
        -GNinja && \
    ninja -C /src/smoframework/build smo-node && \
    # Verify binary works
    /src/smoframework/build/cmd/smo-node/smo-node --version

# =========================================================================
# RUNTIME STAGE (distroless)
# =========================================================================
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Copy smo-node binary from builder
COPY --from=builder /src/smoframework/build/cmd/smo-node/smo-node /usr/local/bin/smo-node

# Create necessary directories
RUN mkdir -p /var/lib/smo /var/lib/smo-mesh /etc/smo

# Use nonroot user (UID 65532)
USER nonroot:nonroot

# Expose default ports
EXPOSE 7777 9090

# Entry point
ENTRYPOINT ["/usr/local/bin/smo-node"]

# Default command shows help
CMD ["--help"]