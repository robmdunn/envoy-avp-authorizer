use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_verifiedpermissions::Client as VerifiedPermissionsClient;
use aws_sdk_verifiedpermissions::types::Decision;
use aws_types::region::Region;
use clap::Parser;
use envoy_types::ext_authz::v3::CheckResponseExt;
use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{debug, error, info, trace, warn, Level};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::fs;
use url::Url;

mod jwt;
mod auth_cache;
mod resource_mapper;
mod telemetry;
mod health;

use jwt::{JwtValidator, JwtError, Claims};
use auth_cache::{AuthorizationCache, Decision as CacheDecision, EntityUid};
use resource_mapper::{ResourceMapper, create_default_resource_mapper};
use telemetry::Telemetry;

use crate::resource_mapper::ResourcePath;

// Global resource mapper
static RESOURCE_MAPPER: Lazy<RwLock<ResourceMapper>> = Lazy::new(|| {
    // Use a dummy value that will be replaced in main()
    RwLock::new(ResourceMapper::new("/api/v*/"))
});

// Helper function to parse query parameters from URL
fn parse_query_params(path: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    
    // Try to parse as URL (add a dummy scheme if needed)
    let url_str = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("http://example.com{}", path)
    };
    
    if let Ok(url) = Url::parse(&url_str) {
        for (key, value) in url.query_pairs() {
            result.insert(key.to_string(), value.to_string());
        }
    }
    
    result
}

// CLI arguments with enhanced configuration options
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// AWS region for Amazon Verified Permissions
    #[arg(short, long, default_value = "us-east-1", env = "AVP_REGION")]
    region: String,

    /// Amazon Verified Permissions policy store ID
    #[arg(short, long, env = "AVP_POLICY_STORE_ID")]
    policy_store_id: String,

    /// Server address to listen on
    #[arg(short, long, default_value = "0.0.0.0:50051", env = "AVP_LISTEN_ADDRESS")]
    address: String,
    
    /// JWT issuer
    #[arg(long, default_value = "https://your-identity-provider.com", env = "AVP_JWT_ISSUER")]
    jwt_issuer: String,
    
    /// JWT audience (optional)
    #[arg(long, env = "AVP_JWT_AUDIENCE")]
    jwt_audience: Option<String>,
    
    /// JWT JWKS URL for validation
    #[arg(long, default_value = "https://your-identity-provider.com/.well-known/jwks.json", env = "AVP_JWKS_URL")]
    jwks_url: String,
    
    /// JWKS cache duration in seconds
    #[arg(long, default_value = "3600", env = "AVP_JWKS_CACHE_DURATION")]
    jwks_cache_duration: u64,
    
    /// Policy cache TTL in seconds
    #[arg(long, default_value = "60", env = "AVP_POLICY_CACHE_TTL")]
    policy_cache_ttl: u64,
    
    /// Maximum policy cache size
    #[arg(long, default_value = "10000", env = "AVP_POLICY_CACHE_SIZE")]
    policy_cache_size: usize,
    
    /// Path to custom resource mapping configuration (optional)
    #[arg(long, env = "AVP_RESOURCE_MAPPING_PATH")]
    resource_mapping_path: Option<String>,

    // API prefix pattern to be stripped
    #[arg(long, default_value = "/api/v*/", env = "AVP_API_PREFIX_PATTERN")]
    api_prefix_pattern: String,
    
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "AVP_LOG_LEVEL")]
    log_level: String,
    
    /// Enable metrics server (default port: 9000)
    #[arg(long, env = "AVP_ENABLE_METRICS")]
    enable_metrics: bool,
}

// Configuration for resource mapping
#[derive(Debug, Deserialize)]
struct ResourceMappingConfig {
    patterns: Vec<ResourceMappingPattern>,
    action_mappings: Vec<ActionMapping>,
}

#[derive(Debug, Deserialize)]
struct ResourceMappingPattern {
    pattern: String,
    resource_type: String,  // Now can contain capture group references like "{resource}"
    resource_id_group: Option<String>,
    parent_type: Option<String>,  // Now can contain capture group references like "{parent}"
    parent_id_group: Option<String>,
    parameter_groups: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ActionMapping {
    path_pattern: String,
    mappings: HashMap<String, String>,
}

// Our authorization service implementation
struct AvpAuthorizationService {
    jwt_validator: JwtValidator,
    auth_cache: Arc<AuthorizationCache>,
    policy_store_id: String,
    avp_client: VerifiedPermissionsClient,
}

impl AvpAuthorizationService {
    async fn new(
        region: String, 
        policy_store_id: String, 
        jwt_issuer: String, 
        jwt_audience: Option<String>, 
        jwks_url: &str,
        jwks_cache_duration: Duration,
        policy_cache_ttl: Duration,
        policy_cache_size: usize,
    ) -> Result<Self> {
        let aws_config = aws_config::defaults(BehaviorVersion::v2025_01_17())
            .region(Region::new(region))
            .retry_config(aws_config::retry::RetryConfig::standard()
                .with_max_attempts(3)
                .with_initial_backoff(Duration::from_millis(100))
                .with_max_backoff(Duration::from_secs(2)))
            .timeout_config(aws_config::timeout::TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(5))
                .operation_attempt_timeout(Duration::from_secs(2))
                .build())
            .load()
            .await;
            
        // Create the Amazon Verified Permissions client
        let avp_client = VerifiedPermissionsClient::new(&aws_config);

        // Create the JWT validator
        let jwt_validator = JwtValidator::new(
            jwks_url.to_string(), 
            jwt_issuer, 
            jwt_audience,
            Some(jwks_cache_duration),
            Some(Duration::from_secs(30)), // 30 second clock skew leeway
        ).await?;
        
        // Create authorization cache
        let auth_cache = Arc::new(AuthorizationCache::new(
            policy_cache_ttl,
            policy_cache_size,
        ));

        Ok(Self {
            jwt_validator,
            auth_cache,
            policy_store_id,
            avp_client,
        })
    }

    // AVP API based check
    async fn check_with_avp_api(
        &self,
        token: &str,
        claims: &Claims,
        method: &str,
        path: &str,
        resource_info: &ResourcePath,
        action: String,
        query_params: &HashMap<String, String>,
        headers: &HashMap<String, String>,
    ) -> Result<Response<CheckResponse>, Status> {
        trace!("Using AVP API for authorization check: path='{}', method='{}'", path, method);
        
        // Extract the action ID (e.g., "read" from "Action::\"read\"")
        let action_id = action.trim_start_matches("Action::\"").trim_end_matches("\"");
        trace!("Extracted action_id: '{}' from action: '{}'", action_id, action);
        
        // Get the resource entity ID from resource info
        let resource_entity_id = resource_info.to_entity_uid();
        let resource_entity_type = resource_info.resource_type.clone();
        debug!("Using resource_entity_id: '{}', resource_entity_type: '{}'", 
            resource_entity_id, resource_entity_type);
        
        // Create context from request information
        let context_pairs = self.create_context_map(method, path, query_params, headers, resource_info, claims);

        // Convert to AVP context format
        let avp_context = match serde_json::to_string(&context_pairs) {
            Ok(json_str) => {
                aws_sdk_verifiedpermissions::types::ContextDefinition::CedarJson(json_str)
            },
            Err(e) => {
                warn!("Failed to serialize context to JSON: {}", e);
                aws_sdk_verifiedpermissions::types::ContextDefinition::CedarJson("{}".to_string())
            }
        };
        
        // Compute cache key for potential caching
        let stable_context = AvpAuthorizationService::create_stable_context_representation(&context_pairs);
        trace!("Context pairs for request: {:#?}", stable_context);

        let context_hash = AuthorizationCache::compute_context_hash(&stable_context);
        debug!("Context hash for request: {} ({} context pairs)", context_hash, context_pairs.len());

        let principal_id = claims.sub.clone();
        let principal = format!("User::\"{principal_id}\"");
        
        // Create EntityUid objects using our custom type
        let principal_entity = EntityUid::new(principal.clone());
        let action_entity = EntityUid::new(action.clone());
        let resource_entity = EntityUid::new(format!("Resource::\"{}\"", resource_entity_id.clone()));
                
        // Try to get result from cache first
        if let Some((cached_decision, diagnostics)) = self.auth_cache.get(
            &principal_entity, 
            &action_entity, 
            &resource_entity, 
            context_hash
        ).await {
            Telemetry::record_cache_hit();
            
            // Return the cached decision
            if cached_decision == CacheDecision::Allow {
                info!("Authorization allowed (cached): principal={}, action={}, resource={}", 
                    principal, action, resource_entity_id);
                
                Ok(Response::new(CheckResponse::with_status(
                    Status::ok("Request authorized"),
                )))
            } else {
                warn!("Authorization denied (cached): principal={}, action={}, resource={}", 
                    principal, action, resource_entity_id);
                
                // Include diagnostics if available
                let message = if let Some(diag) = diagnostics {
                    format!("Request not authorized: {}", diag)
                } else {
                    "Request not authorized".to_string()
                };
                
                Ok(Response::new(CheckResponse::with_status(
                    Status::permission_denied(message),
                )))
            }
        } else {
            Telemetry::record_cache_miss();

            // Call AVP's IsAuthorizedWithToken API
            let eval_timer = Telemetry::time_avp_request();

            let auth_result = self.avp_client
                .is_authorized_with_token()
                .policy_store_id(&self.policy_store_id)
                .identity_token(token)
                .action(aws_sdk_verifiedpermissions::types::ActionIdentifier::builder()
                    .action_id(action_id)
                    .action_type("Action")
                    .build()
                    .map_err(|e| {
                        error!("Failed to build action identifier: {}", e);
                        Status::internal("Failed to build action identifier")
                    })?)
                .resource(aws_sdk_verifiedpermissions::types::EntityIdentifier::builder()
                    .entity_id(resource_entity_id.clone()) // Clone here
                    .entity_type(resource_entity_type)
                    .build()
                    .map_err(|e| {
                        error!("Failed to build entity identifier: {}", e);
                        Status::internal("Failed to build entity identifier")
                    })?)
                .context(avp_context)
                .send()
                .await
                .map_err(|e| {
                    error!("AVP authorization error: {} ({:?})", e, e);
                    if let aws_sdk_verifiedpermissions::error::SdkError::ServiceError(service_err) = &e {
                        error!("Service error details: {:?}", service_err);
                    }
                    Status::internal(format!("Authorization service error: {}", e))
                })?;
                
            // End the evaluation timer
            drop(eval_timer);
                
            // Extract any errors for diagnostics
            let errors_vec: Vec<String> = auth_result.errors().iter()
                .map(|e| {
                    let desc = e.error_description();
                    if !desc.is_empty() {
                        desc.to_string()
                    } else {
                        "Unknown error".to_string()
                    }
                })
                .collect();

            let diagnostics = if !errors_vec.is_empty() {
                Some(errors_vec.join("; "))
            } else {
                None
            };
            
            // Cache the result
            self.auth_cache.put_aws(
                &principal_entity,
                &action_entity,
                &resource_entity,
                context_hash,
                auth_result.decision().clone(),
                diagnostics.clone()
            ).await;
            
            // Return the appropriate response
            if *auth_result.decision() == Decision::Allow {
                info!("Authorization allowed: principal={}, action={}, resource={}", 
                    principal, action, resource_entity_id);
                
                // Record the metric
                Telemetry::record_request(method, path, "allowed");
                
                Ok(Response::new(CheckResponse::with_status(
                    Status::ok("Request authorized"),
                )))
            } else {
                warn!("Authorization denied: principal={}, action={}, resource={}", 
                    principal, action, resource_entity_id);
                
                // Record the metric
                Telemetry::record_request(method, path, "denied");
                
                // Get diagnostics for better error messages
                let message = if let Some(diag) = diagnostics {
                    format!("Request not authorized: {}", diag)
                } else {
                    "Request not authorized".to_string()
                };
                
                Ok(Response::new(CheckResponse::with_status(
                    Status::permission_denied(message),
                )))
            }
        }
    }
    
    fn create_stable_context_representation(context: &HashMap<String, serde_json::Value>) -> String {
        let mut keys: Vec<&String> = context.keys().collect();
        keys.sort(); // Sort keys for stable order
        
        let mut parts = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(value) = context.get(key) {
                // Convert value to a stable string representation
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    _ => value.to_string(),
                };
                parts.push(format!("{}={}", key, value_str));
            }
        }
        
        parts.join(";")
    }

    fn create_context_map(
        &self,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        headers: &HashMap<String, String>,
        resource_info: &ResourcePath, 
        claims: &Claims,
    ) -> HashMap<String, serde_json::Value> {
        let mut context_pairs = HashMap::new();
        
        // Add basic request information
        context_pairs.insert("http_method".to_string(), serde_json::Value::String(method.to_string()));
        context_pairs.insert("http_path".to_string(), serde_json::Value::String(path.to_string()));
        
        // Add query parameters with prefix
        for (k, v) in query_params {
            context_pairs.insert(
                format!("query_{}", k), 
                serde_json::Value::String(v.clone())
            );
        }

        // Add selected headers, EXCLUDING transient headers like x-request-id
        let excluded_headers = [
            "x-request-id", 
            "x-b3-traceid", 
            "x-b3-spanid",
            "x-b3-parentspanid",
            "x-envoy-attempt-count",
        ];
        
        for (k, v) in headers {
            let lower_k = k.to_lowercase();
            if !excluded_headers.iter().any(|&h| lower_k.contains(h)) {
                context_pairs.insert(
                    format!("header_{}", lower_k.replace('-', "_")), 
                    serde_json::Value::String(v.clone())
                );
            }
        }
        
        // Add resource information
        context_pairs.insert(
            "resource_type".to_string(), 
            serde_json::Value::String(resource_info.resource_type.clone())
        );
        
        if let Some(ref id) = resource_info.resource_id {
            context_pairs.insert(
                "resource_id".to_string(), 
                serde_json::Value::String(id.clone())
            );
        }
        
        if let Some(ref parent_type) = resource_info.parent_type {
            context_pairs.insert(
                "parent_type".to_string(), 
                serde_json::Value::String(parent_type.clone())
            );
        }
        
        if let Some(ref parent_id) = resource_info.parent_id {
            context_pairs.insert(
                "parent_id".to_string(), 
                serde_json::Value::String(parent_id.clone())
            );
        }
        
        // Add resource parameters
        for (k, v) in &resource_info.parameters {
            context_pairs.insert(
                format!("param_{}", k), 
                serde_json::Value::String(v.clone())
            );
        }
        
        // Add JWT claims to context
        for (k, v) in &claims.additional_claims {
            context_pairs.insert(
                format!("jwt_{}", k), 
                v.clone()
            );
        }
        
        context_pairs
    }

    fn redact_auth_headers(request: &CheckRequest) -> CheckRequest {
        let mut redacted_request = request.clone();
        
        // Check if we have http attributes with headers
        if let Some(attributes) = &mut redacted_request.attributes {
            if let Some(request_info) = &mut attributes.request {
                if let Some(http) = &mut request_info.http {
                    // Redact authorization header if present
                    for (key, value) in &mut http.headers {
                        if key.to_lowercase() == "authorization" {
                            if value.starts_with("Bearer ") {
                                // Keep first 15 chars of the token
                                let token_start = value.chars().take(15 + 7).collect::<String>();
                                *value = format!("{}...<redacted>", token_start);
                            } else {
                                *value = "<redacted>".to_string();
                            }
                        }
                    }
                }
            }
        }
        
        redacted_request
    }
}

#[tonic::async_trait]
impl Authorization for AvpAuthorizationService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        // Extract the request and decode the attributes (keep this part)
        let check_request = request.into_inner();
        
        // debug!("Received authorization request");
        trace!("Received full check request: {:?}", AvpAuthorizationService::redact_auth_headers(&check_request));
        
        // Get request attributes
        let attributes = match check_request.attributes.as_ref() {
            Some(attr) => attr,
            None => {
                warn!("Request has no attributes");
                return Ok(Response::new(CheckResponse::with_status(
                    Status::unauthenticated("No request attributes provided"),
                )));
            }
        };
        
        // debug!("Attributes: {:?}", attributes);
        // debug!("Request field: {:?}", attributes.request);

        // Get HTTP request details
        let http = match attributes.request.as_ref().and_then(|r| {
            // debug!("Request object: {:?}", r);
            let http_ref = r.http.as_ref();
            // debug!("HTTP field: {:?}", http_ref); 
            http_ref
        }) {
            Some(http) => http,
            None => {
                warn!("Request has no HTTP information");
                return Ok(Response::new(CheckResponse::with_status(
                    Status::unauthenticated("No HTTP information provided"),
                )));
            }
        };
        
        // Extract path and method
        let path = http.path.clone();
        let method = http.method.clone();

        trace!("Authorization request received: method={}, path={}", method, path);
        
        // Start timing the request
        let _request_timer = Telemetry::time_check_request(&method, &path);
        
        // Parse query parameters
        let query_params = parse_query_params(&path);
        
        // Convert headers to a HashMap
        let mut headers = HashMap::new();
        for header in &http.headers {
            headers.insert(header.0.to_lowercase(), header.1.clone());
        }

        // Extract and validate JWT token
        let (token, claims) = match headers.get("authorization") {
            Some(auth) => {
                if let Some(token) = auth.strip_prefix("Bearer ") {
                    // Validate JWT
                    match self.jwt_validator.validate_token(token).await {
                        Ok(claims) => {
                            Telemetry::record_jwt_validation(&claims.iss, true);
                            (token, claims)
                        },
                        Err(err) => {
                            Telemetry::record_jwt_validation(self.jwt_validator.get_issuer(), false);
                            warn!("JWT validation failed: {}", err);
                            let status_message = match err {
                                JwtError::Expired => "Token expired",
                                JwtError::InvalidFormat(_) => "Invalid token format",
                                JwtError::InvalidSignature(_) => "Invalid token signature",
                                JwtError::InvalidIssuer => "Invalid token issuer",
                                JwtError::InvalidAudience => "Invalid token audience",
                                JwtError::NotYetValid => "Token not yet valid",
                                JwtError::KeyNotFound(_) => "JWT key not found",
                                JwtError::JwksFetchError(_) => "Failed to fetch JWT keys",
                                JwtError::HeaderDecodeError(_) => "Failed to decode JWT header",
                                JwtError::JsonWebTokenError(_) => "Token validation error",
                            };
                            return Ok(Response::new(CheckResponse::with_status(
                                Status::unauthenticated(status_message),
                            )));
                        }
                    }
                } else {
                    warn!("Invalid authorization header format");
                    return Ok(Response::new(CheckResponse::with_status(
                        Status::unauthenticated("Invalid authorization header format"),
                    )));
                }
            }
            None => {
                warn!("No authorization header provided");
                return Ok(Response::new(CheckResponse::with_status(
                    Status::unauthenticated("No authorization header provided"),
                )));
            }
        };

        debug!("JWT token validated successfully for user: {}", claims.sub);
        
        // Parse the path into resource information
        let resource_mapper = RESOURCE_MAPPER.read().await;
        let resource_info = match resource_mapper.parse_path(&path) {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to parse path '{}': {}", path, e);
                return Ok(Response::new(CheckResponse::with_status(
                    Status::invalid_argument(format!("Invalid resource path: {}", e)),
                )));
            }
        };

        debug!("Parsed path '{}' to: resource_type={}, resource_id={:?}, parent_type={:?}, parent_id={:?}",
            path,
            resource_info.resource_type,
            resource_info.resource_id,
            resource_info.parent_type,
            resource_info.parent_id);
        
        // Map HTTP method to Cedar action
        let action = resource_mapper.map_method_to_action(&method, &path, &resource_info);
        
        // Use AVP API directly
        return self.check_with_avp_api(token, &claims, &method, &path, &resource_info, action, &query_params, &headers).await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Set up logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();
    
    // Initialize telemetry if enabled
    if args.enable_metrics {
        info!("Initializing metrics server on port 9000");
        Telemetry::init();
    }
    

    // Load resource mapping configuration if provided
    if let Some(path) = &args.resource_mapping_path {
        info!("Loading resource mapping configuration from {}", path);
        match fs::read_to_string(path) {
            Ok(config_str) => {
                trace!("Resource mapping config content: {}", config_str);
                match serde_json::from_str::<ResourceMappingConfig>(&config_str) {
                    Ok(config) => {
                        info!("Found {} patterns and {} action mappings in configuration", 
                            config.patterns.len(), config.action_mappings.len());
                        
                        // Always create a new empty mapper when config file is provided
                        let mut mapper = ResourceMapper::new(&args.api_prefix_pattern);
                        info!("Creating new mapper with custom configuration (default mappings will be ignored)");
                        
                        // Add custom patterns
                        for pattern in &config.patterns {
                            debug!("Adding pattern: '{}' for resource_type: '{}'", 
                                pattern.pattern, pattern.resource_type);
                            
                            let str_params: HashMap<&str, &str> = pattern.parameter_groups
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();

                            if let Err(e) = mapper.add_pattern(
                                &pattern.pattern,
                                &pattern.resource_type,
                                pattern.resource_id_group.as_deref(),
                                pattern.parent_type.as_deref(),
                                pattern.parent_id_group.as_deref(),
                                str_params,
                            ) {
                                error!("Failed to add pattern '{}': {}", pattern.pattern, e);
                            } else {
                                debug!("Successfully added pattern: '{}'", pattern.pattern);
                            }
                        }
                        
                        // Add custom action mappings
                        for mapping in &config.action_mappings {
                            debug!("Adding action mapping for path: '{}'", mapping.path_pattern);
                            
                            let str_action_map: HashMap<&str, &str> = mapping.mappings
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();

                            if let Err(e) = mapper.add_custom_action_mapping(
                                &mapping.path_pattern,
                                str_action_map,
                            ) {
                                error!("Failed to add action mapping for '{}': {}", mapping.path_pattern, e);
                            } else {
                                debug!("Successfully added action mapping for: '{}'", mapping.path_pattern);
                            }
                        }
                        
                        // Replace the global resource mapper
                        {
                            let mut global_mapper = RESOURCE_MAPPER.write().await;
                            *global_mapper = mapper;
                        }
                        
                        // After replacing, dump all registered patterns for debugging
                        {
                            let mapper = RESOURCE_MAPPER.read().await;
                            debug!("Resource mapper now has {} patterns configured", mapper.get_pattern_count());
                            // Skip the detailed logging to avoid issues
                            debug!("Resource mapping configured successfully");
                        }
                        
                        info!("Custom resource mapping configured successfully");
                    },
                    Err(e) => {
                        error!("Failed to parse resource mapping configuration: {}", e);
                    }
                }
            },
            Err(e) => {
                error!("Failed to read resource mapping config file {}: {}", path, e);
            }
        }
    } else {
        // Initialize with default mappings if no config file provided
        info!("No resource mapping configuration file provided, using default mappings");
        let default_mapper = create_default_resource_mapper(&args.api_prefix_pattern);
        let mut global_mapper = RESOURCE_MAPPER.write().await;
        *global_mapper = default_mapper;
    }
    
    // Build the address to listen on
    let addr: SocketAddr = args.address.parse()?;
    
    // Create our authorization service
    info!("Initializing AVP authorization service");
    
    // Create the service with appropriate mode
    let avp_auth_service = AvpAuthorizationService::new(
        args.region, 
        args.policy_store_id.clone(),
        args.jwt_issuer.clone(),
        args.jwt_audience.clone(),
        &args.jwks_url,
        Duration::from_secs(args.jwks_cache_duration),
        Duration::from_secs(args.policy_cache_ttl),
        args.policy_cache_size,
    ).await?;
    
    info!("Starting gRPC server on {}", addr);
    Server::builder()
        .add_service(AuthorizationServer::new(avp_auth_service))
        .add_service(health::new_health_service())
        .serve(addr)
        .await?;
    
    Ok(())
}