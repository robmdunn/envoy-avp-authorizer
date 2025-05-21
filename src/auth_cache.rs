use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use tokio::sync::RwLock;
use tracing::{debug, trace, info};

// Enum to represent authorization decisions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

// Simple EntityUid replacement
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityUid {
    value: String
}

impl EntityUid {
    pub fn new(value: String) -> Self {
        EntityUid { value }
    }
}

impl std::fmt::Display for EntityUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl std::str::FromStr for EntityUid {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(EntityUid::new(s.to_string()))
    }
}

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
        info!("Initializing authorization cache with TTL: {:?}, max size: {}", ttl, max_size);
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
                trace!("Cache hit for {}/{}/{}", principal, action, resource);
                return Some((entry.decision.clone(), entry.diagnostics.clone()));
            } else {
                trace!("Cache entry expired for {}/{}/{}", principal, action, resource);
            }
        } else {
            trace!("Cache miss for {}/{}/{}", principal, action, resource);
        }
        
        None
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
        // Create cache key
        let key = AuthCacheKey {
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            context_hash,
        };

        // Convert AWS decision to our Decision enum
        let decision = match aws_decision {
            aws_sdk_verifiedpermissions::types::Decision::Allow => Decision::Allow,
            _ => Decision::Deny,
        };

        let entry = AuthCacheEntry {
            decision,
            expires_at: Instant::now() + self.ttl,
            diagnostics,
        };

        // Acquire write lock
        let mut cache = self.cache.write().await;
        
        // More efficient cache eviction when full - only evict if we've reached max size
        if cache.len() >= self.max_size {
            self.evict_entries(&mut cache).await;
        }

        // Add the new entry
        cache.insert(key, entry);
        debug!("Cached authorization decision for {}/{}/{}", principal, action, resource);
    }

    async fn evict_entries(&self, cache: &mut tokio::sync::RwLockWriteGuard<'_, HashMap<AuthCacheKey, AuthCacheEntry>>) {
        info!("Authorization cache full, evicting entries");
        
        // First pass: remove expired entries
        let now = Instant::now();
        let mut expired_count = 0;
        
        cache.retain(|_, entry| {
            let expired = entry.expires_at <= now;
            if expired {
                expired_count += 1;
            }
            !expired
        });
        
        // If we removed some expired entries, we're done
        if expired_count > 0 {
            info!("Evicted {} expired entries from authorization cache", expired_count);
            return;
        }
        
        // Second pass: if no expired entries, remove the oldest entries (10% of cache)
        let remove_count = self.max_size / 10;
        if remove_count == 0 {
            return;
        }
        
        // Sort by expiration time to get the oldest entries
        let mut entries: Vec<_> = cache
            .iter()
            .map(|(k, v)| (k.clone(), v.expires_at))
            .collect();
        
        // Sort by expiration time (oldest first)
        entries.sort_by_key(|(_k, exp)| *exp);
        
        // Remove the oldest entries
        for (k, _) in entries.into_iter().take(remove_count) {
            cache.remove(&k);
        }
        
        info!("Evicted {} oldest entries from authorization cache", remove_count);
    }
}