FROM rust:1.87-slim-bookworm AS builder

WORKDIR /usr/src/app

# Install build dependencies needed for OpenSSL and other native dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached unless dependencies change)
RUN cargo build --release && rm src/main.rs

# Copy the actual source code
COPY src ./src

# Build the application (only application code compilation, dependencies are cached)
RUN cargo build --release

# Create a smaller runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m avpuser
USER avpuser
WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/envoy-avp-authorizer /

# Expose the port the service will run on
EXPOSE 50051
EXPOSE 9000

# Command to run the executable
ENTRYPOINT ["/envoy-avp-authorizer"]

# Default arguments if none are provided
CMD ["--help"]