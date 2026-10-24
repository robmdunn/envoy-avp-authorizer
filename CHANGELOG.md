# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- This changelog.
- GitHub releases now include auto-generated release notes listing the PRs
  merged since the previous tag, grouped by label (`.github/release.yml`).

## [0.1.2] - 2026-10-24

Maintenance release: dependency and toolchain updates only. There are no
changes to CLI flags, configuration, or authorization behavior.

### Added

- Istio deployment example ([`examples/istio/istio.md`](examples/istio/istio.md)),
  linked from the README.

### Changed

- Upgraded `jsonwebtoken` from 9.3 to 10.3. Token verification now uses the
  `aws-lc-rs` crypto backend, which was already a dependency through the AWS SDK.
- Upgraded the gRPC stack: `tonic` and `tonic-health` 0.13 → 0.14, `prost`
  0.13 → 0.14, `envoy-types` 0.6 → 0.7.
- Upgraded `sha2` from 0.10 to 0.11 (used for authorization cache keys).
- Upgraded `metrics-exporter-prometheus` from 0.17 to 0.18.
- Upgraded AWS SDK crates: `aws-sdk-verifiedpermissions` 1.80 → 1.87,
  `aws-config` 1.6 → 1.8, `aws-types` 1.3.7 → 1.3.8.
- Minor and patch updates: `anyhow`, `async-trait`, `clap`, `futures`,
  `metrics`, `once_cell`, `regex`, `reqwest`, `serde`, `serde_json`,
  `thiserror`, `tokio`, `tracing`, `tracing-subscriber`.
- The Docker builder image moved from Rust 1.87 to Rust 1.96 to satisfy newer
  dependency MSRVs. Building from source needs a recent stable toolchain.
- CI and release workflows were updated to current major versions of
  `actions/checkout`, `actions/cache`, `actions/upload-artifact`,
  `actions/download-artifact`, `docker/setup-buildx-action`,
  `docker/login-action`, `docker/build-push-action` and
  `softprops/action-gh-release`.
- Dependabot now batches all Cargo updates into a single grouped pull request.

## [0.1.1] - 2025-05-29

First tagged release.

[Unreleased]: https://github.com/robmdunn/envoy-avp-authorizer/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/robmdunn/envoy-avp-authorizer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/robmdunn/envoy-avp-authorizer/releases/tag/v0.1.1
