use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::RwLock; // Replace std::sync::RwLock with tokio::sync::RwLock
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub aud: Option<String>,
    pub roles: Option<Vec<String>>,
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
    JwtError(#[from] jsonwebtoken::errors::Error),
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
    // pub async fn refresh_if_needed(&mut self) -> Result<(), JwtError> {
    //     if self.last_refresh.elapsed() >= self.cache_duration {
    //         self.refresh().await?;
    //     }
    //     Ok(())
    // }
    
    // Forcefully refresh the JWKS cache
    pub async fn refresh(&mut self) -> Result<(), JwtError> {
        let client = reqwest::Client::new();
        let jwks_response = client.get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| JwtError::JwksFetchError(e.to_string()))?;
            
        let jwks_json = jwks_response
            .text()
            .await
            .map_err(|e| JwtError::JwksFetchError(e.to_string()))?;
            
        let jwks: Value = serde_json::from_str(&jwks_json)
            .map_err(|e| JwtError::JwksFetchError(e.to_string()))?;
            
        let keys = jwks["keys"].as_array()
            .ok_or_else(|| JwtError::JwksFetchError("Invalid JWKS format: missing 'keys' array".to_string()))?;
            
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
                        Some(_alg) => {
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
                }
            }
        }
        
        self.last_refresh = Instant::now();
        Ok(())
    }
    
    // Get a key by its ID
    pub fn get_key(&self, kid: &str) -> Option<(&DecodingKey, Algorithm)> {
        self.keys.get(kid).map(|cached| (&cached.key, cached.algorithm))
    }
}

pub struct JwtValidator {
    jwks_cache: RwLock<JwksCache>, // No need for Arc with tokio::sync::RwLock
    issuer: String,
    audience: Option<String>,
}

impl JwtValidator {
    pub async fn new(jwks_url: String, issuer: String, audience: Option<String>) -> Result<Self, JwtError> {
        let mut jwks_cache = JwksCache::new(jwks_url, Duration::from_secs(3600)); // 1 hour cache
        
        // Initialize the cache
        jwks_cache.refresh().await?;
        
        Ok(JwtValidator {
            jwks_cache: RwLock::new(jwks_cache),
            issuer,
            audience,
        })
    }
    
    pub async fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        // Decode JWT header to get the key ID
        let header = decode_header(token)
            .map_err(|e| JwtError::HeaderDecodeError(e.to_string()))?;
            
        let kid = header.kid.ok_or_else(|| 
            JwtError::HeaderDecodeError("No 'kid' found in JWT header".to_string()))?;
            
        // Get the appropriate key from the cache using tokio's async RwLock
        let decoding_key_and_alg = {
            // Acquire a read lock on the cache - note the .await
            let cache = self.jwks_cache.read().await;
            
            cache.get_key(&kid).map(|(key, alg)| (key.clone(), alg))
        };

        // If key not found, refresh cache and try again
        let (decoding_key, algorithm) = match decoding_key_and_alg {
            Some(key_alg) => key_alg,
            None => {
                // Acquire write lock to refresh cache - note the .await
                let mut cache = self.jwks_cache.write().await;
                    
                // Refresh the cache
                cache.refresh().await?;
                
                // Try to get the key again
                match cache.get_key(&kid) {
                    Some((key, alg)) => (key.clone(), alg),
                    None => return Err(JwtError::KeyNotFound(kid)),
                }
            }
        };
        
        // Create validation parameters
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&self.issuer]);
        
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        }
        
        // Decode and validate the token
        let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
        
        // Additional validation
        let claims = token_data.claims;
        
        // Verify token is not expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        if claims.exp < now {
            return Err(JwtError::Expired);
        }
        
        // Verify token is not used before it's valid
        if claims.iat > now {
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