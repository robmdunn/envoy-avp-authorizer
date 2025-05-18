FROM rust:1.87-alpine3.21 AS builder

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release

FROM alpine:3.21
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/envoy-avp-authorizer /usr/local/bin/

ENTRYPOINT ["envoy-avp-authorizer"]