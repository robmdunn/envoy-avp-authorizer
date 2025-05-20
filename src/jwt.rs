use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub aud: Option<String>,
    pub roles: Option<Vec<String>>,
    #[serde(flatten)]
    pub additional_claims: HashMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Token expired")]
    Expired,
    
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),
    
    #[error("Invalid token signature: {0}")]
    InvalidSignature(String),
    
    #[error("Invalid issuer")]
    InvalidIssuer,
    
    #[error("Invalid audience")]
    InvalidAudience,
    
    #[error("Token not yet valid")]
    NotYetValid,
    
    #[error("Key not found for kid: {0}")]
    KeyNotFound(String),
    
    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchError(String),
    
    #[error("Failed to decode JWT header: {0}")]
    HeaderDecodeError(String),
    
    #[error("JWT processing error: {0}")]
    JsonWebTokenError(#[from] jsonwebtoken::errors::Error),
}

// Structure to represent a cached JWK
struct CachedJwk {
    key: DecodingKey,
    algorithm: Algorithm,
    expiry: Instant,
}

// JWKS Cache to avoid excessive network requests
pub struct JwksCache {
    keys: HashMap<String, CachedJwk>,
    jwks_url: String,
    cache_duration: Duration,
    last_refresh: Instant,
}

impl JwksCache {
    pub fn new(jwks_url: String, cache_duration: Duration) -> Self {
        JwksCache {
            keys: HashMap::new(),
            jwks_url,
            cache_duration,
            last_refresh: Instant::now() - cache_duration, // Force immediate refresh on first use
        }
    }
    
    // Refresh the JWKS cache if needed
    pub async fn refresh_if_needed(&mut self) -> Result<(), JwtError> {
        if self.last_refresh.elapsed() >= self.cache_duration {
            debug!("JWKS cache expired, refreshing from {}", self.jwks_url);
            self.refresh().await?;
        }
        Ok(())
    }
    
    // Forcefully refresh the JWKS cache
    pub async fn refresh(&mut self) -> Result<(), JwtError> {
        let client = reqwest::Client::new();
        debug!("Fetching JWKS from {}", self.jwks_url);
        
        let jwks_response = client.get(&self.jwks_url)
            .timeout(Duration::from_secs(5)) // Add timeout
            .send()
            .await
            .map_err(|e| {
                error!("Failed to fetch JWKS: {}", e);
                JwtError::JwksFetchError(e.to_string())
            })?;
            
        let jwks_json = jwks_response
            .text()
            .await
            .map_err(|e| JwtError::JwksFetchError(e.to_string()))?;
            
        let jwks: Value = serde_json::from_str(&jwks_json)
            .map_err(|e| JwtError::JwksFetchError(e.to_string()))?;
            
        let keys = jwks["keys"].as_array()
            .ok_or_else(|| JwtError::JwksFetchError("Invalid JWKS format: missing 'keys' array".to_string()))?;
            
        debug!("Received {} keys from JWKS endpoint", keys.len());
        
        // Clear existing keys
        self.keys.clear();
        
        // Process each key in the JWKS
        for key_value in keys {
            if let Some(kid) = key_value["kid"].as_str() {
                if let Some(kty) = key_value["kty"].as_str() {
                    let algorithm = match key_value["alg"].as_str() {
                        Some("RS256") => Algorithm::RS256,
                        Some("RS384") => Algorithm::RS384,
                        Some("RS512") => Algorithm::RS512,
                        Some("ES256") => Algorithm::ES256,
                        Some("ES384") => Algorithm::ES384,
                        Some("HS256") => Algorithm::HS256,
                        Some("HS384") => Algorithm::HS384,
                        Some("HS512") => Algorithm::HS512,
                        Some(alg) => {
                            warn!("Unsupported algorithm in JWKS: {}", alg);
                            // Skip unsupported algorithms
                            continue;
                        },
                        None => Algorithm::RS256, // Default to RS256 if not specified
                    };
                    
                    // Create decoding key based on key type
                    let decoding_key = match kty {
                        "RSA" => {
                            let n = key_value["n"].as_str()
                                .ok_or_else(|| JwtError::JwksFetchError("Missing 'n' value in RSA JWK".to_string()))?;
                            let e = key_value["e"].as_str()
                                .ok_or_else(|| JwtError::JwksFetchError("Missing 'e' value in RSA JWK".to_string()))?;
                                
                            DecodingKey::from_rsa_components(n, e)
                                .map_err(|e| JwtError::JwksFetchError(format!("Failed to create RSA key: {}", e)))?
                        },
                        "EC" => {
                            let x = key_value["x"].as_str()
                                .ok_or_else(|| JwtError::JwksFetchError("Missing 'x' value in EC JWK".to_string()))?;
                            let y = key_value["y"].as_str()
                                .ok_or_else(|| JwtError::JwksFetchError("Missing 'y' value in EC JWK".to_string()))?;
                                
                            DecodingKey::from_ec_components(x, y)
                                .map_err(|e| JwtError::JwksFetchError(format!("Failed to create EC key: {}", e)))?
                        },
                        "oct" => {
                            let k = key_value["k"].as_str()
                                .ok_or_else(|| JwtError::JwksFetchError("Missing 'k' value in oct JWK".to_string()))?;
                                
                            DecodingKey::from_base64_secret(k)
                                .map_err(|e| JwtError::JwksFetchError(format!("Failed to create symmetric key: {}", e)))?
                        },
                        _ => {
                            warn!("Unsupported key type in JWKS: {}", kty);
                            // Skip unsupported key types
                            continue;
                        }
                    };
                    
                    // Calculate cache expiry
                    let expiry = Instant::now() + self.cache_duration;
                    
                    // Store the key in the cache
                    self.keys.insert(kid.to_string(), CachedJwk {
                        key: decoding_key,
                        algorithm,
                        expiry,
                    });
                    
                    debug!("Added key with kid '{}' to JWKS cache", kid);
                }
            }
        }
        
        self.last_refresh = Instant::now();
        debug!("JWKS cache refreshed successfully with {} keys", self.keys.len());
        Ok(())
    }
    
    // Get a key by its ID
    pub fn get_key(&self, kid: &str) -> Option<(&DecodingKey, Algorithm)> {
        let result = self.keys.get(kid).map(|cached| (&cached.key, cached.algorithm));
        if result.is_none() {
            debug!("Key with kid '{}' not found in JWKS cache", kid);
        }
        result
    }
}

pub struct JwtValidator {
    jwks_cache: RwLock<JwksCache>,
    issuer: String,
    audience: Option<String>,
    clock_skew_leeway: Duration,
}

impl JwtValidator {
    pub async fn new(
        jwks_url: String, 
        issuer: String, 
        audience: Option<String>,
        cache_duration: Option<Duration>,
        clock_skew_leeway: Option<Duration>,
    ) -> Result<Self, JwtError> {
        info!("Initializing JWT validator for issuer: {}, cache duration: {:?}", 
            issuer, cache_duration);

        let cache_duration = cache_duration.unwrap_or(Duration::from_secs(3600)); // Default 1 hour
        let mut jwks_cache = JwksCache::new(jwks_url, cache_duration);
        let clock_skew_leeway = clock_skew_leeway.unwrap_or(Duration::from_secs(30)); // Default 30 seconds
        
        // Initialize the cache
        jwks_cache.refresh().await?;
        
        Ok(JwtValidator {
            jwks_cache: RwLock::new(jwks_cache),
            issuer,
            audience,
            clock_skew_leeway,
        })
    }
    
    pub fn get_issuer(&self) -> &str {
        &self.issuer
    }
    
    pub async fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {

        trace!("Validating JWT token for issuer: {}", self.issuer);
        
        // Decode JWT header to get the key ID
        let header = decode_header(token)
            .map_err(|e| JwtError::HeaderDecodeError(e.to_string()))?;
            
        let kid = header.kid.ok_or_else(|| 
            JwtError::HeaderDecodeError("No 'kid' found in JWT header".to_string()))?;
            
        // Check if cache needs refreshing and get the appropriate key
        let (decoding_key, algorithm) = {
            // Acquire a write lock to check/refresh cache as needed
            let mut cache = self.jwks_cache.write().await;
            
            // Proactively refresh if needed
            cache.refresh_if_needed().await?;
            
            // Try to get the key
            match cache.get_key(&kid) {
                Some((key, alg)) => (key.clone(), alg),
                None => {
                    // Force refresh if key not found
                    debug!("Key not found in cache, forcing refresh");
                    cache.refresh().await?;
                    
                    // Try again after refresh
                    match cache.get_key(&kid) {
                        Some((key, alg)) => (key.clone(), alg),
                        None => return Err(JwtError::KeyNotFound(kid)),
                    }
                }
            }
        };
        
        // Create validation parameters
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&self.issuer]);
        
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        }
        
        // Allow for clock skew
        validation.leeway = self.clock_skew_leeway.as_secs() as u64;
        
        // Decode and validate the token
        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        
        // Additional validation
        let claims = token_data.claims;
        
        // Verify token is not expired (with leeway)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        if claims.exp + (self.clock_skew_leeway.as_secs() as u64) < now {
            return Err(JwtError::Expired);
        }
        
        // Verify token is not used before it's valid (with leeway)
        if claims.iat > now + self.clock_skew_leeway.as_secs() as u64 {
            return Err(JwtError::NotYetValid);
        }
        
        // Verify issuer (double check beyond the validation)
        if claims.iss != self.issuer {
            return Err(JwtError::InvalidIssuer);
        }
        
        // Verify audience if specified
        if let Some(ref expected_aud) = self.audience {
            if let Some(ref token_aud) = claims.aud {
                if token_aud != expected_aud {
                    return Err(JwtError::InvalidAudience);
                }
            } else {
                return Err(JwtError::InvalidAudience);
            }
        }
        
        Ok(claims)
    }
}