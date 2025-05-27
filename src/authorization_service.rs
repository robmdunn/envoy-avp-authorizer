use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_verifiedpermissions::Client as VerifiedPermissionsClient;
use aws_types::region::Region;
use envoy_types::ext_authz::v3::CheckResponseExt;
use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, trace, warn};
use url::Url;

use crate::jwt::{JwtValidator, Claims};
use crate::auth_cache::{AuthorizationCache, ContextHash, Decision as CacheDecision};
use crate::resource_mapper::{ResourceMapper, ResourcePath};
use crate::telemetry::Telemetry;

// Configuration for creating the authorization service
#[derive(Debug)]
pub struct ServiceConfig {
    pub region: String,
    pub policy_store_id: String,
    pub jwt_issuer: String,
    pub jwt_audience: Option<String>,
    pub jwks_url: String,
    pub jwks_cache_duration: Duration,
    pub policy_cache_ttl: Duration,
    pub policy_cache_size: usize,
}

// Request information grouped together
#[derive(Debug)]
pub struct AuthorizationRequest<'a> {
    pub token: &'a str,
    pub claims: &'a Claims,
    pub method: &'a str,
    pub path: &'a str,
    pub resource_info: &'a ResourcePath,
    pub action: String,
    pub query_params: &'a HashMap<String, String>,
    pub headers: &'a HashMap<String, String>,
}

// Context for authorization operations
#[derive(Debug)]
pub struct AuthorizationContext {
    pub principal: String,
    pub action_type: String,
    pub action_id: String,
    pub resource_entity_id: String,
    pub resource_entity_type: String,
    pub context_pairs: HashMap<String, serde_json::Value>,
    pub context_hash: ContextHash,
}

// Context for creating responses
#[derive(Debug)]
pub struct ResponseContext<'a> {
    pub decision: CacheDecision,
    pub diagnostics: Option<String>,
    pub cached: bool,
    pub principal: &'a str,
    pub action_type: &'a str,
    pub action_id: &'a str,
    pub resource_entity_type: &'a str,
    pub resource_entity_id: &'a str,
    pub path: &'a str,
    pub method: &'a str,
    pub resource_info: &'a ResourcePath
}


pub trait Redactable {
    fn redact(&self) -> String;
}

impl Redactable for CheckRequest {
    fn redact(&self) -> String {
        if let Some(attrs) = &self.attributes {
            if let Some(request) = &attrs.request {
                if let Some(http) = &request.http {
                    let mut result = format!("CheckRequest{{ method: {}, path: {}", http.method, http.path);
                    
                    // Check for auth header and redact if present
                    let mut has_auth = false;
                    for (k, v) in &http.headers {
                        if k.to_lowercase() == "authorization" {
                            has_auth = true;
                            let safe = if v.len() > 8 { 
                                format!("{}...", &v[..8]) 
                            } else { 
                                "<redacted>".to_string() 
                            };
                            result.push_str(&format!(", {}: {}", k, safe));
                            break; // Only show the first auth header
                        }
                    }
                    if !has_auth {
                        result.push_str(", no-auth");
                    }
                    
                    result.push_str(" }");
                    result
                } else {
                    "CheckRequest{ no http }".to_string()
                }
            } else {
                "CheckRequest{ no request }".to_string()
            }
        } else {
            "CheckRequest{ no attributes }".to_string()
        }
    }
}

pub struct AvpAuthorizationService {
    jwt_validator: JwtValidator,
    auth_cache: Arc<AuthorizationCache>,
    policy_store_id: String,
    avp_client: VerifiedPermissionsClient,
}

impl AvpAuthorizationService {
    pub async fn new(config: ServiceConfig) -> Result<Self> {
        let aws_config = aws_config::defaults(BehaviorVersion::v2025_01_17())
            .region(Region::new(config.region))
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
            config.jwks_url, 
            config.jwt_issuer, 
            config.jwt_audience,
            Some(config.jwks_cache_duration),
            Some(Duration::from_secs(30)), // 30 second clock skew leeway
        ).await?;
        
        // Create authorization cache
        let auth_cache = Arc::new(AuthorizationCache::new(
            config.policy_cache_ttl,
            config.policy_cache_size,
        ));

        Ok(Self {
            jwt_validator,
            auth_cache,
            policy_store_id: config.policy_store_id,
            avp_client,
        })
    }

    // Main authorization flow - handles both cached and fresh authorization
    async fn authorize_request(&self, request: &AuthorizationRequest<'_>) -> Result<Response<CheckResponse>, Status> {
        trace!("Authorizing request: path='{}', method='{}'", request.path, request.method);
        
        // Create authorization context
        let auth_context = self.create_authorization_context(request)?;
        
        // Try cache first, then AVP API
        let (decision, diagnostics, cached) = match self.check_authorization_cache(&auth_context).await {
            Some((decision, diagnostics)) => {
                Telemetry::record_cache_hit();
                (decision, diagnostics, true)
            },
            None => {
                Telemetry::record_cache_miss();
                let (decision, diagnostics) = self.call_avp_authorization(request, &auth_context).await?;
                
                // Cache the result
                self.cache_authorization_result(&auth_context, &decision, &diagnostics).await;
                
                (decision, diagnostics, false)
            }
        };
        
        // Create response
        let response_context = ResponseContext {
            decision,
            diagnostics,
            cached,
            principal: &auth_context.principal,
            action_type: &auth_context.action_type,
            action_id: &auth_context.action_id,
            resource_entity_type: &auth_context.resource_entity_type,
            resource_entity_id: &auth_context.resource_entity_id,
            path: request.path,
            method: request.method,
            resource_info: request.resource_info
        };
        
        self.create_authorization_response(&response_context)
    }

    // Create authorization context from request
    fn create_authorization_context(&self, request: &AuthorizationRequest<'_>) -> Result<AuthorizationContext, Status> {
        // Parse the action string to extract action_type and action_id
        let (action_type, action_id) = Self::parse_action_string(&request.action);
        debug!("Parsed action: type='{}', id='{}' from full action: '{}'", action_type, action_id, request.action);

        // Get the resource entity ID from resource info
        let resource_entity_id = request.resource_info.resource_id.clone()
            .unwrap_or_else(|| request.resource_info.resource_type.clone());
        let resource_entity_type = request.resource_info.resource_type.clone();
        debug!("Using resource_entity_id: '{}', resource_entity_type: '{}'", 
            resource_entity_id, resource_entity_type);
        
        // Create context from request information
        let context_pairs = self.create_context_map(request);

        let context_hash = AuthorizationCache::hash_context(&context_pairs);
        debug!("Context hash for request: {} ({} context pairs)", context_hash, context_pairs.len());

        let principal_id = request.claims.sub.clone();
        let principal = format!("User::{}", principal_id);

        Ok(AuthorizationContext {
            principal,
            action_type,
            action_id,
            resource_entity_id,
            resource_entity_type,
            context_pairs,
            context_hash,
        })
    }

    // Check authorization cache only
    async fn check_authorization_cache(&self, context: &AuthorizationContext) -> Option<(CacheDecision, Option<String>)> {
        let action = format!("{}::{}", context.action_type, context.action_id);
        let resource = format!("{}::{}", context.resource_entity_type, context.resource_entity_id);
        
        self.auth_cache.get(
            &context.principal,
            &action,
            &resource,
            context.context_hash
        ).await
    }

    // Call AVP API for fresh authorization
    async fn call_avp_authorization(
        &self,
        request: &AuthorizationRequest<'_>,
        context: &AuthorizationContext,
    ) -> Result<(CacheDecision, Option<String>), Status> {
        
        // Convert to AVP context format
        let avp_context = match serde_json::to_string(&context.context_pairs) {
            Ok(json_str) => {
                aws_sdk_verifiedpermissions::types::ContextDefinition::CedarJson(json_str)
            },
            Err(e) => {
                warn!("Failed to serialize context to JSON: {}", e);
                aws_sdk_verifiedpermissions::types::ContextDefinition::CedarJson("{}".to_string())
            }
        };

        // Build entities definition for parent hierarchies
        let entities = self.build_entities_definition(request.resource_info, &context.resource_entity_id, &context.resource_entity_type)?;

        // Call AVP's IsAuthorizedWithToken API
        let eval_timer = Telemetry::time_avp_request();

        let mut request_builder = self.avp_client
            .is_authorized_with_token()
            .policy_store_id(&self.policy_store_id)
            .identity_token(request.token)
            .action(aws_sdk_verifiedpermissions::types::ActionIdentifier::builder()
                .action_id(&context.action_id)
                .action_type(&context.action_type)
                .build()
                .map_err(|e| {
                    error!("Failed to build action identifier: {}", e);
                    Status::internal("Failed to build action identifier")
                })?)
            .resource(aws_sdk_verifiedpermissions::types::EntityIdentifier::builder()
                .entity_id(&context.resource_entity_id)
                .entity_type(&context.resource_entity_type)
                .build()
                .map_err(|e| {
                    error!("Failed to build entity identifier: {}", e);
                    Status::internal("Failed to build entity identifier")
                })?)
            .context(avp_context);

        // Add entities if we have any
        if let Some(entities_def) = entities {
            request_builder = request_builder.entities(entities_def);
        }

        let auth_result = request_builder
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
        
        // Convert AWS decision to our cache decision
        let cache_decision = match auth_result.decision() {
            aws_sdk_verifiedpermissions::types::Decision::Allow => CacheDecision::Allow,
            _ => CacheDecision::Deny,
        };
        
        debug!("Authorization decision from AVP API: {:?}", cache_decision);
        Ok((cache_decision, diagnostics))
    }

    // Cache authorization result
    async fn cache_authorization_result(
        &self,
        context: &AuthorizationContext,
        decision: &CacheDecision,
        diagnostics: &Option<String>,
    ) {
        let aws_decision = match decision {
            CacheDecision::Allow => aws_sdk_verifiedpermissions::types::Decision::Allow,
            CacheDecision::Deny => aws_sdk_verifiedpermissions::types::Decision::Deny,
        };

        let resource = format!("{}::{}", context.resource_entity_type, context.resource_entity_id);
        let action = format!("{}::{}", context.action_type, context.action_id);
        
        self.auth_cache.put_aws(
            &context.principal,
            &action,
            &resource,
            context.context_hash,
            aws_decision,
            diagnostics.clone()
        ).await;
    }

    // Create authorization response
    fn create_authorization_response(&self, context: &ResponseContext<'_>) -> Result<Response<CheckResponse>, Status> {
        match context.decision {
            CacheDecision::Allow => {
                info!("AUTHORIZATION ALLOWED: principal={}, action={}::{}, resource={}::{}, path={}, cached={}", 
                    context.principal, context.action_type, context.action_id, 
                    context.resource_entity_type, context.resource_entity_id, 
                    context.path, context.cached);
                
                // Record the metric
                Telemetry::record_request(context.method, &context.resource_info.matched_pattern, "allowed");
                
                Ok(Response::new(CheckResponse::with_status(
                    Status::ok("Request authorized"),
                )))
            },
            CacheDecision::Deny => {
                warn!("AUTHORIZATION DENIED: principal={}, action={}::{}, resource={}::{}, path={}, cached={}", 
                    context.principal, context.action_type, context.action_id, 
                    context.resource_entity_type, context.resource_entity_id, 
                    context.path, context.cached);
                if let Some(ref diag) = context.diagnostics {
                    debug!("  diagnostics: {}", diag);
                }
                
                // Record the metric
                Telemetry::record_request(context.method, &context.resource_info.matched_pattern, "denied");
                
                // Include diagnostics if available
                let message = if let Some(diag) = &context.diagnostics {
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

    fn create_context_map(&self, request: &AuthorizationRequest<'_>) -> HashMap<String, serde_json::Value> {
        let mut context_pairs = HashMap::new();
        
        // Add basic request information
        context_pairs.insert("http_method".to_string(), serde_json::Value::String(request.method.to_string()));
        context_pairs.insert("http_path".to_string(), serde_json::Value::String(request.path.to_string()));
        
        // Add query parameters with prefix
        for (k, v) in request.query_params {
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
        
        for (k, v) in request.headers {
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
            serde_json::Value::String(request.resource_info.resource_type.clone())
        );

        if let Some(ref id) = request.resource_info.resource_id {
            context_pairs.insert(
                "resource_id".to_string(), 
                serde_json::Value::String(id.clone())
            );
        }

        // Add parent information from the parents array
        for (i, parent) in request.resource_info.parents.iter().enumerate() {
            context_pairs.insert(
                format!("parent_{}_type", i), 
                serde_json::Value::String(parent.parent_type.clone())
            );
            context_pairs.insert(
                format!("parent_{}_id", i), 
                serde_json::Value::String(parent.parent_id.clone())
            );
        }
        
        // Add JWT claims to context
        for (k, v) in &request.claims.additional_claims {
            context_pairs.insert(
                format!("jwt_{}", k), 
                v.clone()
            );
        }
        
        context_pairs
    }

    // Build entities definition for AVP from resource hierarchy
    fn build_entities_definition(
        &self,
        resource_info: &ResourcePath,
        resource_entity_id: &str,
        resource_entity_type: &str,
    ) -> Result<Option<aws_sdk_verifiedpermissions::types::EntitiesDefinition>, Status> {
        if resource_info.parents.is_empty() {
            trace!("No parent entities to include");
            return Ok(None);
        }

        let mut entity_items = Vec::new();

        // Add parent entities
        for parent in &resource_info.parents {
            let parent_identifier = aws_sdk_verifiedpermissions::types::EntityIdentifier::builder()
                .entity_type(&parent.parent_type)
                .entity_id(&parent.parent_id)
                .build()
                .map_err(|e| {
                    error!("Failed to build parent entity identifier: {}", e);
                    Status::internal("Failed to build parent entity identifier")
                })?;

            let entity_item = aws_sdk_verifiedpermissions::types::EntityItem::builder()
                .identifier(parent_identifier)
                .build();

            entity_items.push(entity_item);
            debug!("Added parent entity: {}::{}", parent.parent_type, parent.parent_id);
        }

        // Add the resource entity itself with parent relationships
        if !entity_items.is_empty() {
            let mut resource_parents = Vec::new();
            for parent in &resource_info.parents {
                let parent_identifier = aws_sdk_verifiedpermissions::types::EntityIdentifier::builder()
                    .entity_type(&parent.parent_type)
                    .entity_id(&parent.parent_id)
                    .build()
                    .map_err(|e| {
                        error!("Failed to build parent identifier for resource: {}", e);
                        Status::internal("Failed to build parent identifier")
                    })?;
                resource_parents.push(parent_identifier);
            }

            let resource_identifier = aws_sdk_verifiedpermissions::types::EntityIdentifier::builder()
                .entity_type(resource_entity_type)
                .entity_id(resource_entity_id)
                .build()
                .map_err(|e| {
                    error!("Failed to build resource entity identifier: {}", e);
                    Status::internal("Failed to build resource entity identifier")
                })?;

            let resource_entity_item = aws_sdk_verifiedpermissions::types::EntityItem::builder()
                .identifier(resource_identifier)
                .set_parents(Some(resource_parents))
                .build();

            entity_items.push(resource_entity_item);
            debug!("Added resource entity with {} parents: {}", resource_info.parents.len(), resource_entity_id);
        }

        if tracing::enabled!(tracing::Level::TRACE) {
            // Debug log the full entity structure
            trace!("Built entities definition with {} entities", entity_items.len());
            for (i, item) in entity_items.iter().enumerate() {
                if let Some(identifier) = item.identifier() {
                    trace!("  entity[{}]: {}::{}", i, identifier.entity_type(), identifier.entity_id());
                } else {
                    trace!("  entity[{}]: <no identifier>", i);
                }
                
                let parents = item.parents();
                if !parents.is_empty() {
                    for (j, parent) in parents.iter().enumerate() {
                        trace!("    parent[{}]: {}::{}", j, parent.entity_type(), parent.entity_id());
                    }
                }
            }
        }

        let entities_def = aws_sdk_verifiedpermissions::types::EntitiesDefinition::EntityList(entity_items);
        Ok(Some(entities_def))
    }

    // Helper function to parse action strings into (action_type, action_id)
    fn parse_action_string(action: &str) -> (String, String) {
        trace!("Parsing action string: '{}'", action);
        
        let result = if action.starts_with("Action::\"") && action.ends_with("\"") {
            let action_id = action.trim_start_matches("Action::\"").trim_end_matches("\"");
            trace!("Parsed legacy action format: action_type='Action', action_id='{}'", action_id);
            ("Action".to_string(), action_id.to_string())
        } else if let Some(last_separator) = action.rfind("::") {
            let action_type = &action[..last_separator];
            let action_id = &action[last_separator + 2..];
            
            if !action_type.is_empty() && !action_id.is_empty() {
                trace!("Parsed namespaced action: action_type='{}', action_id='{}'", action_type, action_id);
                (action_type.to_string(), action_id.to_string())
            } else {
                trace!("Using fallback parsing: action_type='Action', action_id='{}'", action);
                ("Action".to_string(), action.to_string())
            }
        } else {
            trace!("Using fallback parsing: action_type='Action', action_id='{}'", action);
            ("Action".to_string(), action.to_string())
        };
        
        result
    }

    pub fn parse_query_params(path: &str) -> HashMap<String, String> {
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
}

#[tonic::async_trait]
impl Authorization for AvpAuthorizationService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        // Start timing the request
        let _request_timer = Telemetry::time_check_request();

        // Extract the request and safely log it
        let check_request = request.into_inner();
        trace!("Received request: {}", check_request.redact());
        
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
        
        // Extract path and method
        let path = http.path.clone();
        let method = http.method.clone();

        trace!("Authorization request received: method={}, path={}", method, path);
        
        // Parse query parameters
        let query_params = Self::parse_query_params(&path);
        
        // Convert headers to a HashMap
        let headers: HashMap<String, String> = http.headers.iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        // Extract and validate JWT token
        let (token, claims) = match self.jwt_validator.authenticate_request(&headers).await {
            Ok((token, claims)) => (token, claims),
            Err(status_message) => {
                return Ok(Response::new(CheckResponse::with_status(
                    Status::unauthenticated(status_message),
                )));
            }
        };

        debug!("JWT token validated successfully for user: {}", claims.sub);
        
        // Parse the path into resource information
        let resource_mapper = ResourceMapper::global().await;
        let resource_info = match resource_mapper.parse_path(&path) {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to parse path '{}': {}", path, e);
                return Ok(Response::new(CheckResponse::with_status(
                    Status::invalid_argument(format!("Invalid resource path: {}", e)),
                )));
            }
        };

        debug!("Parsed path '{}' to: resource_type={}, resource_id={:?}, parents={:?}",
            path,
            resource_info.resource_type,
            resource_info.resource_id,
            resource_info.parents);

        // Map HTTP method to Cedar action
        let action = resource_mapper.map_method_to_action(&method, &path, &resource_info);
        
        // Create authorization request
        let auth_request = AuthorizationRequest {
            token: &token,
            claims: &claims,
            method: &method,
            path: &path,
            resource_info: &resource_info,
            action,
            query_params: &query_params,
            headers: &headers,
        };
        
        // Authorize the request
        self.authorize_request(&auth_request).await
    }
}