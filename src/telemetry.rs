use metrics::{counter, histogram};
use tracing::info;
use std::time::Instant;

// Define metric names
const METRIC_AVP_REQUESTS_TOTAL: &str = "avp_requests_total";
const METRIC_AVP_REQUEST_DURATION_SECONDS: &str = "avp_request_duration_seconds";
const METRIC_JWT_VALIDATION_TOTAL: &str = "jwt_validation_total";
const METRIC_JWT_VALIDATION_FAILURES: &str = "jwt_validation_failures";
const METRIC_ENTITY_FETCH_TOTAL: &str = "entity_fetch_total";
const METRIC_ENTITY_FETCH_FAILURES: &str = "entity_fetch_failures";
const METRIC_ENTITY_FETCH_DURATION_SECONDS: &str = "entity_fetch_duration_seconds";
const METRIC_CACHE_HITS: &str = "avp_cache_hits_total";
const METRIC_CACHE_MISSES: &str = "avp_cache_misses_total";
const METRIC_CEDAR_EVALUATION_DURATION_SECONDS: &str = "cedar_evaluation_duration_seconds";
const METRIC_JWKS_REFRESH_TOTAL: &str = "jwks_refresh_total";
const METRIC_JWKS_REFRESH_FAILURES: &str = "jwks_refresh_failures";

// Telemetry wrapper for recording metrics
pub struct Telemetry;

impl Telemetry {
    // Initialize metrics (called once at startup)
    pub fn init() {
        info!("Initializing telemetry on port 9000");
        let addr = ([0, 0, 0, 0], 9000);
        
        // Configure metrics (could be updated to export to Prometheus, etc.)
        if let Err(e) = metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(addr)
            .install() {
            eprintln!("Failed to install Prometheus metrics exporter: {}", e);
        }
    }

    // Record an authorization request
    pub fn record_request(method: &str, path: &str, status: &str) {
        counter!(
            METRIC_AVP_REQUESTS_TOTAL,
            "method" => method.to_string(),
            "path" => path.to_string(),
            "status" => status.to_string()
        ).increment(1);
    }

    // Start timing a request and return a guard that will record the duration when dropped
    pub fn time_request(method: &str, path: &str) -> RequestTimer {
        RequestTimer {
            start: Instant::now(),
            method: method.to_string(),
            path: path.to_string(),
        }
    }

    // Record a JWT validation
    pub fn record_jwt_validation(issuer: &str, success: bool) {
        counter!(
            METRIC_JWT_VALIDATION_TOTAL,
            "issuer" => issuer.to_string()
        ).increment(1);

        if !success {
            counter!(
                METRIC_JWT_VALIDATION_FAILURES,
                "issuer" => issuer.to_string()
            ).increment(1);
        }
    }

    // Record entity fetching
    pub fn record_entity_fetch(entity_type: &str, success: bool) {
        counter!(
            METRIC_ENTITY_FETCH_TOTAL,
            "entity_type" => entity_type.to_string()
        ).increment(1);

        if !success {
            counter!(
                METRIC_ENTITY_FETCH_FAILURES,
                "entity_type" => entity_type.to_string()
            ).increment(1);
        }
    }

    // Time entity fetching
    pub fn time_entity_fetch(entity_type: &str) -> EntityFetchTimer {
        EntityFetchTimer {
            start: Instant::now(),
            entity_type: entity_type.to_string(),
        }
    }

    // Record cache usage
    pub fn record_cache_hit() {
        counter!(METRIC_CACHE_HITS).increment(1);
    }

    pub fn record_cache_miss() {
        counter!(METRIC_CACHE_MISSES).increment(1);
    }

    // Time Cedar policy evaluation
    pub fn time_cedar_evaluation() -> CedarEvaluationTimer {
        CedarEvaluationTimer {
            start: Instant::now(),
        }
    }

    // Record JWKS refresh
    pub fn record_jwks_refresh(issuer: &str, success: bool) {
        counter!(
            METRIC_JWKS_REFRESH_TOTAL,
            "issuer" => issuer.to_string()
        ).increment(1);

        if !success {
            counter!(
                METRIC_JWKS_REFRESH_FAILURES,
                "issuer" => issuer.to_string()
            ).increment(1);
        }
    }
}

// Timer guard for request duration
pub struct RequestTimer {
    start: Instant,
    method: String,
    path: String,
}

impl Drop for RequestTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        histogram!(
            METRIC_AVP_REQUEST_DURATION_SECONDS,
            "method" => self.method.clone(),
            "path" => self.path.clone()
        ).record(duration.as_secs_f64());
    }
}

// Timer guard for entity fetch duration
pub struct EntityFetchTimer {
    start: Instant,
    entity_type: String,
}

impl Drop for EntityFetchTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        histogram!(
            METRIC_ENTITY_FETCH_DURATION_SECONDS,
            "entity_type" => self.entity_type.clone()
        ).record(duration.as_secs_f64());
    }
}

// Timer guard for Cedar policy evaluation
pub struct CedarEvaluationTimer {
    start: Instant,
}

impl Drop for CedarEvaluationTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        histogram!(METRIC_CEDAR_EVALUATION_DURATION_SECONDS)
            .record(duration.as_secs_f64());
    }
}