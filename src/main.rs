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
                                JwtError::JwtError(_) => "Token validation error",
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
        
        // Use the validated subject from JWT as principal ID
        let principal_id = claims.sub;
        
        // Extract resource and action from the request
        // For example, we can use path and method to determine these
        let path = http.path.clone();
        let method = http.method.clone();
        
        // Map HTTP method to Cedar action
        let action = format!("http_{}", method.to_lowercase());
        
        // In a real implementation, you'd parse the path to determine the resource
        // For simplicity, we'll just use the path as the resource ID
        let resource_id = path;
        
        // Build the Cedar authorization request
        // This is simplified - in a real implementation you'd map HTTP attributes 
        // to your Cedar schema properly
        let principal = format!("User::\"{principal_id}\"");
        let resource = format!("Resource::\"{resource_id}\"");
        let action = format!("Action::\"{action}\"");
        
        debug!("Checking authorization: principal={}, action={}, resource={}", 
            principal, action, resource);
        
        let principal_entity: EntityUid = principal.parse().unwrap();
        let action_entity: EntityUid = action.parse().unwrap();
        let resource_entity: EntityUid = resource.parse().unwrap();

        let cedar_request = CedarRequest::new(
            principal_entity,
            action_entity,
            resource_entity,
            Context::empty(),
            None,
        ).unwrap();

        // Perform the authorization check
        let auth_result = match self.authorizer.read().await.is_authorized(&cedar_request, &Entities::empty()).await {

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