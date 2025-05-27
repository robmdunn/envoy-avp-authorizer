use anyhow::Result;
use clap::Parser;
use envoy_types::ext_authz::v3::pb::AuthorizationServer;
use std::net::SocketAddr;
use std::time::Duration;
use tonic::transport::Server;
use tracing::{error, info, Level};

mod jwt;
mod auth_cache;
mod resource_mapper;
mod telemetry;
mod health;
mod authorization_service;

use authorization_service::{AvpAuthorizationService, ServiceConfig};
use resource_mapper::ResourceMapper;
use telemetry::Telemetry;

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

    // Initialize resource mapper
    ResourceMapper::initialize(
        args.resource_mapping_path.as_deref(), 
        &args.api_prefix_pattern
    ).await.map_err(|e| {
        error!("Failed to initialize resource mapper: {}", e);
        anyhow::anyhow!("Resource mapper initialization failed: {}", e)
    })?;
    
    // Build the address to listen on
    let addr: SocketAddr = args.address.parse()?;
    
    // Create our authorization service
    info!("Initializing AVP authorization service");
    
    // Create service configuration
    let service_config = ServiceConfig {
        region: args.region,
        policy_store_id: args.policy_store_id,
        jwt_issuer: args.jwt_issuer,
        jwt_audience: args.jwt_audience,
        jwks_url: args.jwks_url,
        jwks_cache_duration: Duration::from_secs(args.jwks_cache_duration),
        policy_cache_ttl: Duration::from_secs(args.policy_cache_ttl),
        policy_cache_size: args.policy_cache_size,
    };
    
    // Create the service with configuration
    let avp_auth_service = AvpAuthorizationService::new(service_config).await?;
    
    info!("Starting gRPC server on {}", addr);
    Server::builder()
        .add_service(AuthorizationServer::new(avp_auth_service))
        .add_service(health::new_health_service())
        .serve(addr)
        .await?;
    
    Ok(())
}