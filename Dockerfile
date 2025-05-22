FROM rust:1.87-slim-bookworm AS builder

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release

# Create a smaller runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

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
ENTRYPOINT ["envoy-avp-authorizer"]

# Default arguments if none are provided
CMD ["--help"]