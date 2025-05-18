use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_verifiedpermissions::Client as VerifiedPermissionsClient;
use aws_types::region::Region;
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::Request as CedarRequest;
use cedar_policy::Decision;
use cedar_policy::Entities;
use cedar_policy::EntityUid;
use cedar_policy::Context;
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
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn, debug, error};

mod jwt;
use jwt::{JwtValidator, JwtError};

// Resource information structure for parsing API paths
#[derive(Debug, Clone)]
struct ResourceInfo {
    resource_type: String,
    resource_id: Option<String>,
    parent_type: Option<String>,
    parent_id: Option<String>,
}

impl ResourceInfo {
    fn to_entity_uid(&self) -> String {
        match (&self.resource_id, &self.parent_type, &self.parent_id) {
            // Resource with ID, with parent
            (Some(id), Some(parent_type), Some(parent_id)) => {
                format!("{}::{parent_type}::{parent_id}::{}", self.resource_type, id)
            },
            // Resource with ID, no parent
            (Some(id), _, _) => {
                format!("{}::{}", self.resource_type, id)
            },
            // Resource collection with parent
            (None, Some(parent_type), Some(parent_id)) => {
                format!("{}Collection::{parent_type}::{parent_id}", self.resource_type)
            },
            // Resource collection, no parent
            _ => {
                format!("{}Collection", self.resource_type)
            }
        }
    }
}

// CLI arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// AWS region
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
}

// Function to parse a path into resource information
fn parse_path(path: &str) -> ResourceInfo {
    // Remove API prefix if present
    let clean_path = path.trim_start_matches("/api/v1").trim_start_matches('/');
    
    // Split the path into segments
    let segments: Vec<&str> = clean_path.split('/').collect();
    
    match segments.len() {
        // /resources
        1 => {
            ResourceInfo {
                resource_type: segments[0].to_string(),
                resource_id: None,
                parent_type: None,
                parent_id: None,
            }
        },
        // /resources/{id}
        2 => {
            ResourceInfo {
                resource_type: segments[0].to_string(),
                resource_id: Some(segments[1].to_string()),
                parent_type: None,
                parent_id: None,
            }
        },
        // /resources/{id}/subresources
        3 => {
            ResourceInfo {
                resource_type: segments[2].to_string(),
                resource_id: None,
                parent_type: Some(segments[0].to_string()),
                parent_id: Some(segments[1].to_string()),
            }
        },
        // /resources/{id}/subresources/{sub_id}
        4 => {
            ResourceInfo {
                resource_type: segments[2].to_string(),
                resource_id: Some(segments[3].to_string()),
                parent_type: Some(segments[0].to_string()),
                parent_id: Some(segments[1].to_string()),
            }
        },
        // Default or more complex paths - we can extend this logic as needed
        _ => {
            ResourceInfo {
                resource_type: "unknown".to_string(),
                resource_id: None,
                parent_type: None,
                parent_id: None,
            }
        }
    }
}

// Map HTTP method to Cedar action based on resource info
fn map_method_to_action(method: &str, resource_info: &ResourceInfo) -> String {
    let base_action = match method.to_uppercase().as_str() {
        "GET" => "read",
        "POST" => "create",
        "PUT" => "update",
        "DELETE" => "delete",
        "PATCH" => "patch",
        "HEAD" => "read_metadata",
        "OPTIONS" => "get_permissions",
        _ => "access",
    };
    
    // If it's a collection resource (no ID), adjust the action accordingly
    let action = match (&resource_info.resource_id, base_action) {
        (None, "read") => "list",
        (None, "update") => "update_bulk",
        (None, "delete") => "delete_bulk",
        _ => base_action,
    };
    
    format!("Action::\"{}\"", action)
}

// Our authorization service implementation
struct AvpAuthorizationService {
    authorizer: Arc<RwLock<Authorizer<PolicySetProvider, EntityProvider>>>,
    jwt_validator: JwtValidator, 
}

impl AvpAuthorizationService {
    async fn new(region: String, policy_store_id: String, jwt_issuer: String, jwt_audience: Option<String>, jwks_url: &str) -> Result<Self> {
        // Set up AWS SDK configuration
        let aws_config = aws_config::defaults(BehaviorVersion::v2025_01_17())
            .region(Region::new(region)) // Use Region::new instead of parse
            .load()
            .await;
            
        // Create the Amazon Verified Permissions client
        let avp_client = VerifiedPermissionsClient::new(&aws_config);
        
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
        
        // Create the authorizer configuration
        let config = AuthorizerConfigBuilder::default()
            .policy_set_provider(Arc::new(policy_set_provider))
            .entity_provider(Arc::new(entity_provider))
            .build()
            .unwrap();
        
        // Create the authorizer with the configuration
        let authorizer = Authorizer::new(config);
        
        // Create the JWT validator with JWKS support
        let jwt_validator = JwtValidator::new(
            jwks_url.to_string(), 
            jwt_issuer, 
            jwt_audience
        ).await?;

        Ok(Self {
            authorizer: Arc::new(RwLock::new(authorizer)),
            jwt_validator,
        })
    }
    
    // Method to fetch and build entities for Cedar authorization
    async fn get_entities_for_request(&self, 
                                     claims: &jwt::Claims,
                                     resource_info: &ResourceInfo) -> Result<Entities, Status> {
        // We need to directly use the entity provider
        // First, obtain a read lock on the authorizer
        let _authorizer = self.authorizer.read().await;
        
        // Since Cedar 4.4.0 doesn't expose entity_provider() directly,
        // we need to create a minimal set of entities with the important info
        
        // Start with empty entities - we'll build what we need
        let mut _entities_vec = Vec::<Entities>::new();
        
        // We'll use the Cedar EntityId API to represent resources
        
        // Get user entity - in a production app, you'd fetch this from Cedar/AVP
        // Here we create a minimal entity representation for the user
        let _principal_uid: EntityUid = format!("User::\"{}\"", claims.sub).parse()
            .map_err(|_| Status::internal("Failed to parse principal UID"))?;
            
        // Add the user information - in a real implementation, you'd fetch this from AVP
        
        // If resource has an ID, create entity for it
        if let Some(id) = &resource_info.resource_id {
            let _resource_uid: EntityUid = format!("Resource::\"{}::{}\"", 
                resource_info.resource_type, id).parse()
                .map_err(|_| Status::internal("Failed to parse resource UID"))?;
                
            // In a real implementation, you'd fetch the resource entity from AVP
        }
        
        // For parent resources, if applicable
        if let (Some(parent_type), Some(parent_id)) = (&resource_info.parent_type, &resource_info.parent_id) {
            let _parent_uid: EntityUid = format!("Resource::\"{}::{}\"", 
                parent_type, parent_id).parse()
                .map_err(|_| Status::internal("Failed to parse parent resource UID"))?;
                
            // In a real implementation, you'd fetch the parent entity from AVP 
        }
        
        // For now, we'll use empty entities since the actual entity content would come from AVP
        // In a real implementation, you'd use the Cedar entity provider to populate this
        Ok(Entities::empty())
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
        
        // Convert headers to a HashMap for easier access
        let mut headers = HashMap::new();
        for header in &http.headers {
            headers.insert(header.0.to_lowercase(), header.1.clone());
        }

        // Extract and validate JWT token
        let claims = match headers.get("authorization") {
            Some(auth) => {
                if let Some(token) = auth.strip_prefix("Bearer ") {
                    // Proper JWT validation - note the .await here
                    match self.jwt_validator.validate_token(token).await {
                        Ok(claims) => claims,
                        Err(err) => {
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
        
        // Extract path and method from the request
        let path = http.path.clone();
        let method = http.method.clone();
        
        // Parse the path into resource information
        let resource_info = parse_path(&path);
        
        // Use the validated subject from JWT as principal ID
        let principal_id = claims.sub.clone();
        let principal = format!("User::\"{principal_id}\"");
        let principal_entity: EntityUid = principal.parse().unwrap();
        
        // Map HTTP method to Cedar action based on resource type
        let action = map_method_to_action(&method, &resource_info);
        let action_entity: EntityUid = action.parse().unwrap();
        
        // Get resource entity from path information
        let resource = format!("Resource::\"{}\"", resource_info.to_entity_uid());
        let resource_entity: EntityUid = resource.parse().unwrap();

        debug!("Checking authorization: principal={}, action={}, resource={}", 
            principal, action, resource);

        // Create Cedar request
        let cedar_request = CedarRequest::new(
            principal_entity,
            action_entity,
            resource_entity,
            Context::empty(),
            None,
        ).unwrap();

        // Get entities for this request
        let entities = match self.get_entities_for_request(&claims, &resource_info).await {
            Ok(e) => e,
            Err(status) => {
                warn!("Failed to get entities for request: {:?}", status);
                // Fall back to empty entities rather than failing the request
                Entities::empty()
            }
        };

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
        
        // Check the decision
        if matches!(auth_result.decision(), Decision::Allow) {
            info!("Authorization allowed: principal={}, action={}, resource={}", 
                principal, action, resource);
            
            // Allow the request and add any custom headers if needed
            Ok(Response::new(CheckResponse::with_status(
                Status::ok("Request authorized"),
            )))
        } else {
            warn!("Authorization denied: principal={}, action={}, resource={}", 
                principal, action, resource);
            
            // Deny the request
            Ok(Response::new(CheckResponse::with_status(
                Status::permission_denied("Request not authorized"),
            )))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let args = Args::parse();
    
    // Build the address to listen on
    let addr: SocketAddr = args.address.parse()?;
    
    // Create our authorization service
    info!("Initializing AVP authorization service");
    let avp_auth_service = AvpAuthorizationService::new(
        args.region, 
        args.policy_store_id,
        args.jwt_issuer,
        args.jwt_audience,
        &args.jwks_url
    ).await?;
    
    // Build and start the gRPC server
    info!("Starting gRPC server on {}", addr);
    Server::builder()
        .add_service(AuthorizationServer::new(avp_auth_service))
        .serve(addr)
        .await?;
    
    Ok(())
}