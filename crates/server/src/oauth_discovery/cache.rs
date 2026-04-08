use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use super::metadata::AuthorizationServerMetadata;

const CACHE_TTL_SECONDS: i64 = 900; // 15 minutes

#[derive(Clone)]
pub struct DiscoveryCache {
    inner: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

struct CacheEntry {
    metadata: AuthorizationServerMetadata,
    expires_at: DateTime<Utc>,
}

impl DiscoveryCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, as_url: &str) -> Option<AuthorizationServerMetadata> {
        let cache = self.inner.read().await;
        cache.get(as_url).and_then(|entry| {
            if entry.expires_at > Utc::now() {
                Some(entry.metadata.clone())
            } else {
                None
            }
        })
    }

    pub async fn put(&self, as_url: String, metadata: AuthorizationServerMetadata) {
        let mut cache = self.inner.write().await;
        cache.insert(
            as_url,
            CacheEntry {
                metadata,
                expires_at: Utc::now() + chrono::Duration::seconds(CACHE_TTL_SECONDS),
            },
        );
    }

    pub async fn invalidate(&self, as_url: &str) {
        let mut cache = self.inner.write().await;
        cache.remove(as_url);
    }
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: "https://as.example.com".to_string(),
            authorization_endpoint: "https://as.example.com/authorize".to_string(),
            token_endpoint: "https://as.example.com/token".to_string(),
            registration_endpoint: None,
            response_types_supported: vec![],
            grant_types_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
            code_challenge_methods_supported: vec![],
            scopes_supported: vec![],
            revocation_endpoint: None,
        }
    }

    #[tokio::test]
    async fn test_cache_get_put() {
        let cache = DiscoveryCache::new();
        cache
            .put("https://as.example.com".to_string(), sample_meta())
            .await;
        let got = cache.get("https://as.example.com").await.unwrap();
        assert_eq!(got.issuer, "https://as.example.com");
    }

    #[tokio::test]
    async fn test_cache_ttl_expiry() {
        let cache = DiscoveryCache::new();
        // Manually insert an expired entry
        {
            let mut inner = cache.inner.write().await;
            inner.insert(
                "https://as.example.com".to_string(),
                CacheEntry {
                    metadata: sample_meta(),
                    expires_at: Utc::now() - chrono::Duration::seconds(1),
                },
            );
        }
        assert!(cache.get("https://as.example.com").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidate() {
        let cache = DiscoveryCache::new();
        cache
            .put("https://as.example.com".to_string(), sample_meta())
            .await;
        cache.invalidate("https://as.example.com").await;
        assert!(cache.get("https://as.example.com").await.is_none());
    }
}
