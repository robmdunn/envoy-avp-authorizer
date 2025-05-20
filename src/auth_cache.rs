use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use cedar_policy::{EntityUid, Response as CedarResponse, Decision};
use tokio::sync::RwLock;
use tracing::{debug, trace, info};

// Define a struct to represent a cache key
#[derive(Debug, Clone, Eq)]
struct AuthCacheKey {
    principal: String,
    action: String,
    resource: String,
    context_hash: u64,  // Hash of the context for comparison
}

impl PartialEq for AuthCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.principal == other.principal &&
        self.action == other.action &&
        self.resource == other.resource &&
        self.context_hash == other.context_hash
    }
}

impl Hash for AuthCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.principal.hash(state);
        self.action.hash(state);
        self.resource.hash(state);
        self.context_hash.hash(state);
    }
}

// Define a struct to represent a cache entry
struct AuthCacheEntry {
    decision: Decision,
    expires_at: Instant,
    diagnostics: Option<String>,
}

// The authorization cache
pub struct AuthorizationCache {
    cache: RwLock<HashMap<AuthCacheKey, AuthCacheEntry>>,
    ttl: Duration,
    max_size: usize,
}

impl AuthorizationCache {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        AuthorizationCache {
            cache: RwLock::new(HashMap::with_capacity(max_size)),
            ttl,
            max_size,
        }
    }

    // Compute a context hash for caching
    pub fn compute_context_hash<S: std::hash::Hash>(context: &S) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        
        let mut hasher = DefaultHasher::new();
        context.hash(&mut hasher);
        hasher.finish()
    }

    // Try to get a cached decision
    pub async fn get(
        &self, 
        principal: &EntityUid, 
        action: &EntityUid, 
        resource: &EntityUid, 
        context_hash: u64
    ) -> Option<(Decision, Option<String>)> {
        let key = AuthCacheKey {
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            context_hash,
        };

        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(&key) {
            if entry.expires_at > Instant::now() {
                debug!("Cache hit for {}/{}/{}", principal, action, resource);
                return Some((entry.decision, entry.diagnostics.clone()));
            } else {
                debug!("Cache entry expired for {}/{}/{}", principal, action, resource);
            }
        } else {
            trace!("Cache miss for {}/{}/{}", principal, action, resource);
        }
        
        None
    }

    // Store a decision in the cache
    pub async fn put(
        &self,
        principal: &EntityUid,
        action: &EntityUid,
        resource: &EntityUid,
        context_hash: u64,
        result: &CedarResponse,
    ) {
        let key = AuthCacheKey {
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            context_hash,
        };

        let entry = AuthCacheEntry {
            decision: result.decision(),
            expires_at: Instant::now() + self.ttl,
            diagnostics: {
                // Check if there are any errors in the diagnostics
                let diag = result.diagnostics();
                if diag.errors().next().is_some() {
                    // We have errors, convert them to a simple string representation
                    let error_string = diag.errors()
                        .map(|err| err.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");
                    Some(error_string)
                } else {
                    None
                }
            },
        };

        let mut cache = self.cache.write().await;
        
        // Check if we need to evict entries (simple approach: clear half the cache when full)
        if cache.len() >= self.max_size {
            info!("Authorization cache full, evicting entries");
            
            // Collect keys to remove (expired entries + oldest entries if needed)
            let now = Instant::now();
            let mut entries: Vec<_> = cache.iter()
                .map(|(k, v)| (k.clone(), v.expires_at))
                .collect();
            
            // Sort by expiration time (expired first, then oldest)
            entries.sort_by_key(|(_k, exp)| *exp);
            
            // Remove expired entries first
            let expired_count = entries.iter().take_while(|(_k, exp)| *exp <= now).count();
            
            // If no expired entries or not enough space freed, remove oldest entries up to half the cache
            let remove_count = if expired_count > 0 {
                expired_count
            } else {
                self.max_size / 10
            };
            
            // Remove the selected entries
            for (k, _) in entries.into_iter().take(remove_count) {
                cache.remove(&k);
            }
            
            info!("Evicted {} entries from authorization cache", remove_count);
        }

        // Add the new entry
        cache.insert(key, entry);
        debug!("Cached authorization decision for {}/{}/{}", principal, action, resource);
    }

    // Store a decision in the cache using AWS types
    pub async fn put_aws(
        &self,
        principal: &EntityUid,
        action: &EntityUid,
        resource: &EntityUid,
        context_hash: u64,
        aws_decision: aws_sdk_verifiedpermissions::types::Decision,
        diagnostics: Option<String>,
    ) {
        let key = AuthCacheKey {
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            context_hash,
        };

        // Convert AWS decision to Cedar decision
        let cedar_decision = match aws_decision {
            aws_sdk_verifiedpermissions::types::Decision::Allow => Decision::Allow,
            _ => Decision::Deny,
        };

        let entry = AuthCacheEntry {
            decision: cedar_decision,
            expires_at: Instant::now() + self.ttl,
            diagnostics,
        };

        let mut cache = self.cache.write().await;
        
        // Check if we need to evict entries (simple approach: clear half the cache when full)
        if cache.len() >= self.max_size {
            info!("Authorization cache full, evicting entries");
            
            // Collect keys to remove (expired entries + oldest entries if needed)
            let now = Instant::now();
            let mut entries: Vec<_> = cache.iter()
                .map(|(k, v)| (k.clone(), v.expires_at))
                .collect();
            
            // Sort by expiration time (expired first, then oldest)
            entries.sort_by_key(|(_k, exp)| *exp);
            
            // Remove expired entries first
            let expired_count = entries.iter().take_while(|(_k, exp)| *exp <= now).count();
            
            // If no expired entries or not enough space freed, remove oldest entries up to half the cache
            let remove_count = if expired_count > 0 {
                expired_count
            } else {
                self.max_size / 10
            };
            
            // Remove the selected entries
            for (k, _) in entries.into_iter().take(remove_count) {
                cache.remove(&k);
            }
            
            info!("Evicted {} entries from authorization cache", remove_count);
        }

        // Add the new entry
        cache.insert(key, entry);
        debug!("Cached authorization decision for {}/{}/{}", principal, action, resource);
    }

    // Remove all entries from the cache
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        let count = cache.len();
        cache.clear();
        info!("Cleared {} entries from authorization cache", count);
    }

    // Remove expired entries (can be called periodically)
    pub async fn remove_expired(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        let before_count = cache.len();
        
        cache.retain(|_, entry| entry.expires_at > now);
        
        let removed = before_count - cache.len();
        if removed > 0 {
            debug!("Removed {} expired entries from authorization cache", removed);
        }
    }
}