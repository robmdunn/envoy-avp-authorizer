use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_verifiedpermissions::Client as VerifiedPermissionsClient;
use aws_types::region::Region;
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::{Request as CedarRequest, Decision, Schema};
use cedar_policy::{Entities, EntityUid, Context};
use avp_local_agent::public::{
    entity_provider::EntityProvider,
    policy_set_provider::PolicySetProvider,
};
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
use tracing::{info, warn, debug, error, Level};
use once_cell::sync::Lazy;
use tokio::sync::mpsc;
use serde::Deserialize;
use std::fs;
use url::Url;

mod jwt;
mod auth_cache;
mod resource_mapper;
mod telemetry;
mod health;

use jwt::{JwtValidator, JwtError, Claims};
use auth_cache::AuthorizationCache;
use resource_mapper::{ResourceMapper, create_default_resource_mapper};
use telemetry::Telemetry;

// Policy refresh channel for background refresh
type PolicyRefreshSender = mpsc::Sender<()>;
type PolicyRefreshReceiver = mpsc::Receiver<()>;

// Global resource mapper
static RESOURCE_MAPPER: Lazy<RwLock<ResourceMapper>> = Lazy::new(|| {
    RwLock::new(create_default_resource_mapper())
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
    #[arg(short, long, default_value = "us-east-1")]
    region: String,

    /// Amazon Verified Permissions policy store ID
    #[arg(short, long)]
    policy_store_id: String,

    /// Server address to listen on
    #[arg(short, long, default_value = "0.0.0.0:50051")]
    address: String,
    
    /// JWT issuer
    #[arg(long, default_value = "https://your-identity-provider.com")]
    jwt_issuer: String,
    
    /// JWT audience (optional)
    #[arg(long)]
    jwt_audience: Option<String>,
    
    /// JWT JWKS URL for validation
    #[arg(long, default_value = "https://your-identity-provider.com/.well-known/jwks.json")]
    jwks_url: String,
    
    /// JWKS cache duration in seconds
    #[arg(long, default_value = "3600")]
    jwks_cache_duration: u64,
    
    /// Policy cache TTL in seconds
    #[arg(long, default_value = "60")]
    policy_cache_ttl: u64,
    
    /// Maximum policy cache size
    #[arg(long, default_value = "10000")]
    policy_cache_size: usize,
    
    /// Policy refresh interval in seconds
    #[arg(long, default_value = "300")]
    policy_refresh_interval: u64,
    
    /// Path to Cedar schema file (optional)
    #[arg(long)]
    schema_path: Option<String>,
    
    /// Path to custom resource mapping configuration (optional)
    #[arg(long)]
    resource_mapping_path: Option<String>,
    
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
    
    /// Enable metrics server (default port: 9000)
    #[arg(long)]
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
    resource_type: String,
    resource_id_group: Option<String>,
    parent_type: Option<String>,
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
    authorizer: Arc<RwLock<Authorizer<PolicySetProvider, EntityProvider>>>,
    jwt_validator: JwtValidator, 
    auth_cache: Arc<AuthorizationCache>,
    schema: Option<Schema>,
    policy_refresh_sender: PolicyRefreshSender,
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
        schema_path: Option<String>,
    ) -> Result<(Self, PolicyRefreshReceiver)> {
        // Set up AWS SDK configuration with retry and timeout settings
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
        
        // Load schema if provided
        let schema: Option<Schema> = if let Some(path) = schema_path {
            info!("Loading Cedar schema from {}", path);
            match fs::read_to_string(&path) {
                Ok(schema_str) => {
                    match Schema::from_json_str(&schema_str) {
                        Ok(schema) => {
                            info!("Successfully loaded Cedar schema");
                            Some(schema)
                        },
                        Err(e) => {
                            error!("Failed to parse Cedar schema: {}", e);
                            None
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to read schema file {}: {}", path, e);
                    None
                }
            }
        } else {
            None
        };
        
        // Create policy provider from Amazon Verified Permissions
        let policy_set_provider = PolicySetProvider::from_client(
            policy_store_id.clone(), 
            avp_client.clone()
        )?;
        
        // Create entity provider from Amazon Verified Permissions
        let entity_provider = EntityProvider::from_client(
            policy_store_id, 
            avp_client
        )?;
        
        // Create the authorizer configuration with the schema if available
        let config = if let Some(_schema) = &schema {
            AuthorizerConfigBuilder::default()
                .policy_set_provider(Arc::new(policy_set_provider))
                .entity_provider(Arc::new(entity_provider))
                .build()
                .unwrap()
        } else {
            AuthorizerConfigBuilder::default()
                .policy_set_provider(Arc::new(policy_set_provider))
                .entity_provider(Arc::new(entity_provider))
                .build()
                .unwrap()
        };
        
        // Create the authorizer with the configuration
        let authorizer = Authorizer::new(config);
        
        // Create the JWT validator with JWKS support
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
        
        // Create policy refresh channel
        let (tx, rx) = mpsc::channel::<()>(1);

        Ok((Self {
            authorizer: Arc::new(RwLock::new(authorizer)),
            jwt_validator,
            auth_cache,
            schema,
            policy_refresh_sender: tx,
        }, rx))
    }
    
    // Method to fetch entities for Cedar authorization
    async fn get_entities_for_request(
        &self, 
        claims: &Claims,
        resource_info: &resource_mapper::ResourcePath
    ) -> Result<Entities, Status> {
        let timer = Telemetry::time_entity_fetch(&resource_info.resource_type);
        
        // Get a list of entity UIDs we need to fetch
        let mut entity_uids = Vec::new();
        
        // User principal entity
        let principal_uid: EntityUid = format!("User::\"{}\"", claims.sub).parse()
            .map_err(|e| {
                Telemetry::record_entity_fetch("User", false);
                error!("Failed to parse principal UID: {}", e);
                Status::internal("Failed to parse principal UID")
            })?;
        
        entity_uids.push(principal_uid.clone());
        
        // Resource entity if it has an ID
        if let Some(id) = &resource_info.resource_id {
            let resource_uid: EntityUid = format!("Resource::\"{}::{}\"", 
                resource_info.resource_type, id).parse()
                .map_err(|e| {
                    Telemetry::record_entity_fetch(&resource_info.resource_type, false);
                    error!("Failed to parse resource UID: {}", e);
                    Status::internal("Failed to parse resource UID")
                })?;
                
            entity_uids.push(resource_uid);
        }
        
        // Parent resource if applicable
        if let (Some(parent_type), Some(parent_id)) = (&resource_info.parent_type, &resource_info.parent_id) {
            let parent_uid: EntityUid = format!("Resource::\"{}::{}\"", 
                parent_type, parent_id).parse()
                .map_err(|e| {
                    Telemetry::record_entity_fetch(parent_type, false);
                    error!("Failed to parse parent resource UID: {}", e);
                    Status::internal("Failed to parse parent resource UID")
                })?;
                
            entity_uids.push(parent_uid);
        }
        
        // Use the Entities from Authorizer.is_authorized() instead
        let entities = Entities::empty();
        
        // Record successful entity fetch
        for uid in &entity_uids {
            // Use namespace_components from paste-3.txt to get entity type
            let entity_type = match uid.id().unescaped() {
                s if s.contains("::") => s.split("::").next().unwrap_or("Unknown").to_string(),
                _ => "Unknown".to_string()
            };
            Telemetry::record_entity_fetch(&entity_type, true);
        }
        
        // Drop the timer
        drop(timer);
        
        Ok(entities)
    }

    
    // Trigger a policy refresh
    async fn trigger_policy_refresh(&self) -> Result<(), Status> {
        debug!("Triggering policy refresh");
        
        // Send signal to the background task
        self.policy_refresh_sender.send(()).await.map_err(|e| {
            error!("Failed to trigger policy refresh: {}", e);
            Status::internal("Failed to trigger policy refresh")
        })?;
        
        Ok(())
    }
    
    // Background task for policy refreshing
    async fn run_policy_refresh_task(
        authorizer: Arc<RwLock<Authorizer<PolicySetProvider, EntityProvider>>>,
        auth_cache: Arc<AuthorizationCache>,
        mut rx: PolicyRefreshReceiver,
        interval: Duration,
    ) {
        info!("Starting policy refresh background task");
        
        // Create a ticker for periodic refresh
        let mut interval_timer = tokio::time::interval(interval);
        
        loop {
            tokio::select! {
                // Handle manual refresh requests
                _ = rx.recv() => {
                    debug!("Received manual policy refresh request");
                    Self::refresh_policies(&authorizer, &auth_cache).await;
                }
                
                // Handle periodic refresh
                _ = interval_timer.tick() => {
                    debug!("Periodic policy refresh triggered");
                    Self::refresh_policies(&authorizer, &auth_cache).await;
                }
            }
        }
    }
    
    // Refresh policies and entities
    async fn refresh_policies(
        authorizer: &Arc<RwLock<Authorizer<PolicySetProvider, EntityProvider>>>,
        auth_cache: &Arc<AuthorizationCache>,
    ) {
        debug!("Refreshing policies and entities");
        
        // Use CedarRequest to clearly indicate this is Cedar's Request type, not Tonic's
        match CedarRequest::new(
            "User::\"refresh\"".parse().unwrap(),
            "Action::\"refresh\"".parse().unwrap(),
            "Resource::\"system\"".parse().unwrap(),
            Context::empty(),
            None,
        ) {
            Ok(refresh_req) => {
                // This will trigger policy and entity provider to fetch fresh data
                let _ = authorizer.read().await.is_authorized(&refresh_req, &Entities::empty()).await;
                info!("Successfully refreshed policy set and entities");
            },
            Err(e) => {
                error!("Failed to create refresh request: {}", e);
            }
        }
        
        // Clear the authorization cache
        auth_cache.clear().await;
        
        debug!("Policy and entity refresh completed");
    }
}

#[tonic::async_trait]
impl Authorization for AvpAuthorizationService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        // Extract the request and decode the attributes
        let check_request = request.into_inner();
        
        debug!("Received authorization request");
        
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
        
        // Get HTTP request details
        let http = match attributes.request.as_ref().and_then(|r| r.http.as_ref()) {
            Some(http) => http,
            None => {
                warn!("Request has no HTTP information");
                return Ok(Response::new(CheckResponse::with_status(
                    Status::unauthenticated("No HTTP information provided"),
                )));
            }
        };
        
        // Extract path and method from the request for metrics
        let path = http.path.clone();
        let method = http.method.clone();
        
        // Start timing the request
        let request_timer = Telemetry::time_request(&method, &path);
        
        // Parse query parameters
        let query_params = parse_query_params(&path);
        
        // Convert headers to a HashMap for easier access
        let mut headers = HashMap::new();
        for header in &http.headers {
            headers.insert(header.0.to_lowercase(), header.1.clone());
        }

        // Extract and validate JWT token
        let claims = match headers.get("authorization") {
            Some(auth) => {
                if let Some(token) = auth.strip_prefix("Bearer ") {
                    // Proper JWT validation
                    match self.jwt_validator.validate_token(token).await {
                        Ok(claims) => {
                            Telemetry::record_jwt_validation(&claims.iss, true);
                            claims
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
        
        // Use the validated subject from JWT as principal ID
        let principal_id = claims.sub.clone();
        let principal = format!("User::\"{principal_id}\"");
        let principal_entity: EntityUid = principal.parse().unwrap();
        
        // Map HTTP method to Cedar action based on resource type
        let action = resource_mapper.map_method_to_action(&method, &path, &resource_info);
        let action_entity: EntityUid = action.parse().unwrap();
        
        // Get resource entity from path information
        let resource = format!("Resource::\"{}\"", resource_info.to_entity_uid());
        let resource_entity: EntityUid = resource.parse().unwrap();

        // Create context from request information
        // let request_context = resource_mapper.create_request_context(
        //     &method, 
        //     &path, 
        //     &query_params, 
        //     &headers
        // );
        
        // Merge with resource context
        // let resource_context = resource_info.to_context();
        // Modified approach for creating the merged context
        let merged_context = {
            // Create a simple HashMap of String -> String values
            let mut context_pairs = HashMap::new();
            
            // Add basic request information
            context_pairs.insert("http_method".to_string(), method.to_string());
            context_pairs.insert("http_path".to_string(), path.to_string());
            
            // Add query parameters with prefix
            for (k, v) in &query_params {
                context_pairs.insert(format!("query_{}", k), v.clone());
            }
            
            // Add selected headers
            for (k, v) in &headers {
                context_pairs.insert(format!("header_{}", k.replace('-', "_")), v.clone());
            }
            
            // Add resource information
            context_pairs.insert("resource_type".to_string(), resource_info.resource_type.clone());
            
            if let Some(ref id) = resource_info.resource_id {
                context_pairs.insert("resource_id".to_string(), id.clone());
            }
            
            if let Some(ref parent_type) = resource_info.parent_type {
                context_pairs.insert("parent_type".to_string(), parent_type.clone());
            }
            
            if let Some(ref parent_id) = resource_info.parent_id {
                context_pairs.insert("parent_id".to_string(), parent_id.clone());
            }
            
            // Add resource parameters
            for (k, v) in &resource_info.parameters {
                context_pairs.insert(format!("param_{}", k), v.clone());
            }
            
            // Add JWT claims to context
            for (k, v) in &claims.additional_claims {
                context_pairs.insert(format!("jwt_{}", k), v.to_string());
            }
            
            // Create a JSON string from the map
            match serde_json::to_string(&context_pairs) {
                Ok(json_str) => match Context::from_json_str(&json_str, None) {
                    Ok(context) => context,
                    Err(e) => {
                        debug!("Failed to create context from JSON: {}", e);
                        Context::empty()
                    }
                },
                Err(e) => {
                    debug!("Failed to serialize context to JSON: {}", e);
                    Context::empty()
                }
            }
        };
        
        // Compute context hash for cache key
        let context_hash = AuthorizationCache::compute_context_hash(&format!("{:?}", merged_context));


        debug!("Checking authorization: principal={}, action={}, resource={}", 
            principal, action, resource);

        // Try to get result from cache first
        if let Some((decision, diagnostics)) = self.auth_cache.get(
            &principal_entity, 
            &action_entity, 
            &resource_entity, 
            context_hash
        ).await {
            Telemetry::record_cache_hit();
            
            debug!("Using cached authorization decision: {:?}", decision);
            
            // Return the cached decision
            return if matches!(decision, Decision::Allow) {
                info!("Authorization allowed (cached): principal={}, action={}, resource={}", 
                    principal, action, resource);
                
                Ok(Response::new(CheckResponse::with_status(
                    Status::ok("Request authorized"),
                )))
            } else {
                warn!("Authorization denied (cached): principal={}, action={}, resource={}", 
                    principal, action, resource);
                
                // Include diagnostics if available
                let message = if let Some(diag) = diagnostics {
                    format!("Request not authorized: {}", diag)
                } else {
                    "Request not authorized".to_string()
                };
                
                Ok(Response::new(CheckResponse::with_status(
                    Status::permission_denied(message),
                )))
            };
        }
        
        Telemetry::record_cache_miss();
        
        // Create Cedar request
        let cedar_request = CedarRequest::new(
            principal_entity.clone(),
            action_entity.clone(),
            resource_entity.clone(),
            merged_context,
            None,
        ).unwrap();

        // Get entities for this request
        let entities = match self.get_entities_for_request(&claims, &resource_info).await {
            Ok(e) => e,
            Err(status) => {
                warn!("Failed to get entities for request: {:?}", status);
                return Ok(Response::new(CheckResponse::with_status(status)));
            }
        };

        // Time the Cedar policy evaluation
        let eval_timer = Telemetry::time_cedar_evaluation();
        
        // Perform the authorization check with the entities
        let auth_result = match self.authorizer.read().await.is_authorized(&cedar_request, &entities).await {
            Ok(result) => result,
            Err(err) => {
                error!("Authorization error: {}", err);
                return Ok(Response::new(CheckResponse::with_status(
                    Status::internal("Authorization system error"),
                )));
            }
        };
        
        // End the evaluation timer
        drop(eval_timer);
        
        // Cache the authorization result
        self.auth_cache.put(
            &principal_entity, 
            &action_entity, 
            &resource_entity, 
            context_hash, 
            &auth_result
        ).await;
        
        // Check the decision
        if matches!(auth_result.decision(), Decision::Allow) {
            info!("Authorization allowed: principal={}, action={}, resource={}", 
                principal, action, resource);
            
            // Record the metric
            Telemetry::record_request(&method, &path, "allowed");
            
            // Allow the request and add any custom headers if needed
            Ok(Response::new(CheckResponse::with_status(
                Status::ok("Request authorized"),
            )))
        } else {
            warn!("Authorization denied: principal={}, action={}, resource={}", 
                principal, action, resource);
            
            // Record the metric
            Telemetry::record_request(&method, &path, "denied");
            
            // Get diagnostics for better error messages
            let message = if auth_result.diagnostics().errors().next().is_some() {
                let errors = auth_result.diagnostics().errors()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                format!("Request not authorized: {}", errors)
            } else {
                "Request not authorized".to_string()
            };
            
            // Deny the request
            Ok(Response::new(CheckResponse::with_status(
                Status::permission_denied(message),
            )))
        }
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
                match serde_json::from_str::<ResourceMappingConfig>(&config_str) {
                    Ok(config) => {
                        info!("Configuring custom resource mapping with {} patterns and {} action mappings", 
                            config.patterns.len(), config.action_mappings.len());
                        
                        let mut mapper = create_default_resource_mapper();
                        
                        // Add custom patterns
                        for pattern in config.patterns {
                            let mut param_groups = HashMap::new();
                            for (k, v) in &pattern.parameter_groups {
                                param_groups.insert(k.clone(), v.clone());
                            }
                            
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
                            }
                        }
                        
                        // Add custom action mappings
                        for mapping in config.action_mappings {
                            let mut action_map = HashMap::new();
                            for (k, v) in &mapping.mappings {
                                action_map.insert(k.clone(), v.clone());
                            }
                            
                            let str_action_map: HashMap<&str, &str> = mapping.mappings
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();

                            if let Err(e) = mapper.add_custom_action_mapping(
                                &mapping.path_pattern,
                                str_action_map,
                            ) {
                                error!("Failed to add action mapping for '{}': {}", mapping.path_pattern, e);
                            }
                        }
                        
                        // Replace the global resource mapper
                        let mut global_mapper = RESOURCE_MAPPER.write().await;
                        *global_mapper = mapper;
                        
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
    }
    
    // Build the address to listen on
    let addr: SocketAddr = args.address.parse()?;
    
    // Create our authorization service
    info!("Initializing AVP authorization service");
    let (avp_auth_service, policy_refresh_rx) = AvpAuthorizationService::new(
        args.region, 
        args.policy_store_id.clone(),
        args.jwt_issuer.clone(),
        args.jwt_audience.clone(),
        &args.jwks_url,
        Duration::from_secs(args.jwks_cache_duration),
        Duration::from_secs(args.policy_cache_ttl),
        args.policy_cache_size,
        args.schema_path,
    ).await?;
    
    // Start the policy refresh background task
    let authorizer_clone = avp_auth_service.authorizer.clone();
    let auth_cache_clone = avp_auth_service.auth_cache.clone();
    let policy_refresh_interval = Duration::from_secs(args.policy_refresh_interval);
    
    tokio::spawn(async move {
        AvpAuthorizationService::run_policy_refresh_task(
            authorizer_clone,
            auth_cache_clone,
            policy_refresh_rx,
            policy_refresh_interval,
        ).await;
    });
    
    info!("Starting gRPC server on {}", addr);
    Server::builder()
        .add_service(AuthorizationServer::new(avp_auth_service))
        .add_service(health::new_health_service())  // Add health service
        .serve(addr)
        .await?;
    
    Ok(())
}