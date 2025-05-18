use std::collections::HashMap;
use cedar_policy::{Context};
use tracing::debug;
use regex::{Regex, RegexSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceMappingError {
    #[error("Invalid path format: {0}")]
    InvalidPathFormat(String),
    
    #[error("Failed to match resource pattern: {0}")]
    PatternMatchFailed(String),
    
    #[error("Missing required path parameter: {0}")]
    MissingParameter(String),

    #[error("Failed to convert value to RestrictedExpression: {0}")]
    ValueConversionError(String),
}

// ResourcePath stores the basic components of a resource
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePath {
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub parent_type: Option<String>,
    pub parent_id: Option<String>,
    pub parameters: HashMap<String, String>,
}

impl ResourcePath {
    pub fn to_entity_uid(&self) -> String {
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
    
    pub fn to_context(&self) -> Context {
        // Create a simple HashMap of String -> String values
        let mut context_pairs = HashMap::new();
        
        // Add basic resource information
        context_pairs.insert("resource_type".to_string(), self.resource_type.clone());

        if let Some(ref id) = self.resource_id {
            context_pairs.insert("resource_id".to_string(), id.clone());
        }
        
        if let Some(ref parent_type) = self.parent_type {
            context_pairs.insert("parent_type".to_string(), parent_type.clone());
        }
        
        if let Some(ref parent_id) = self.parent_id {
            context_pairs.insert("parent_id".to_string(), parent_id.clone());
        }
        
        // Add any additional parameters
        for (key, value) in &self.parameters {
            context_pairs.insert(format!("param_{}", key), value.clone());
        }
        
        // Use Cedar's Context::from_json_str() method instead
        match serde_json::to_string(&context_pairs) {
            Ok(json_str) => match Context::from_json_str(&json_str, None) {
                Ok(context) => context,
                Err(_) => Context::empty(),
            },
            Err(_) => Context::empty(),
        }
    }
}

// A resource pattern for mapping paths to resources
#[derive(Debug, Clone)]
struct ResourcePattern {
    pattern: String,
    regex: Regex,
    resource_type: String,
    resource_id_group: Option<String>,
    parent_type: Option<String>,
    parent_id_group: Option<String>,
    parameter_groups: HashMap<String, String>,
}

// ResourceMapper maps HTTP paths to Cedar resources
pub struct ResourceMapper {
    patterns: Vec<ResourcePattern>,
    pattern_set: RegexSet,
    default_action_map: HashMap<String, String>,
    custom_action_maps: Vec<(Regex, HashMap<String, String>)>,
}

impl ResourceMapper {
    pub fn new() -> Self {
        let patterns = Vec::new();
        let pattern_set = RegexSet::new([""]).unwrap(); // Dummy set, will be replaced
        
        // Default HTTP method to Cedar action mapping
        let default_action_map = {
            let mut map = HashMap::new();
            map.insert("GET".to_string(), "read".to_string());
            map.insert("POST".to_string(), "create".to_string());
            map.insert("PUT".to_string(), "update".to_string());
            map.insert("DELETE".to_string(), "delete".to_string());
            map.insert("PATCH".to_string(), "patch".to_string());
            map.insert("HEAD".to_string(), "read_metadata".to_string());
            map.insert("OPTIONS".to_string(), "get_permissions".to_string());
            map
        };
        
        ResourceMapper {
            patterns,
            pattern_set,
            default_action_map,
            custom_action_maps: Vec::new(),
        }
    }
    
    // Add a resource pattern for mapping
    pub fn add_pattern(
        &mut self,
        pattern: &str,
        resource_type: &str,
        resource_id_group: Option<&str>,
        parent_type: Option<&str>,
        parent_id_group: Option<&str>,
        parameter_groups: HashMap<&str, &str>,
    ) -> Result<(), ResourceMappingError> {
        // Convert the pattern to a regex pattern
        let regex_pattern = Self::pattern_to_regex(pattern)?;
        
        // Create a regex from the pattern
        let regex = Regex::new(&regex_pattern)
            .map_err(|e| ResourceMappingError::PatternMatchFailed(e.to_string()))?;
            
        // Convert parameter groups to owned strings
        let parameter_groups = parameter_groups.into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            
        // Add the pattern
        self.patterns.push(ResourcePattern {
            pattern: pattern.to_string(),
            regex,
            resource_type: resource_type.to_string(),
            resource_id_group: resource_id_group.map(ToString::to_string),
            parent_type: parent_type.map(ToString::to_string),
            parent_id_group: parent_id_group.map(ToString::to_string),
            parameter_groups,
        });
        
        // Update the pattern set
        self.update_pattern_set();
        
        Ok(())
    }
    
    // Add a custom action mapping for specific path patterns
    pub fn add_custom_action_mapping(
        &mut self,
        path_pattern: &str,
        action_map: HashMap<&str, &str>,
    ) -> Result<(), ResourceMappingError> {
        let regex_pattern = Self::pattern_to_regex(path_pattern)?;
        
        let regex = Regex::new(&regex_pattern)
            .map_err(|e| ResourceMappingError::PatternMatchFailed(e.to_string()))?;
            
        let action_map = action_map.into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            
        self.custom_action_maps.push((regex, action_map));
        
        Ok(())
    }
    
    // Update the pattern set after adding patterns
    fn update_pattern_set(&mut self) {
        let patterns: Vec<String> = self.patterns.iter()
            .map(|p| p.regex.to_string())
            .collect();
            
        self.pattern_set = RegexSet::new(&patterns)
            .unwrap_or_else(|_| RegexSet::new(&[""]).unwrap());
    }
    
    // Convert a pattern with placeholders to a regex pattern
    fn pattern_to_regex(pattern: &str) -> Result<String, ResourceMappingError> {
        let mut regex_pattern = pattern.to_string();
        
        // Replace path parameters like {id} with regex capture groups
        let param_regex = Regex::new(r"\{([^}]+)\}")
            .map_err(|_| ResourceMappingError::InvalidPathFormat("Invalid parameter format".to_string()))?;
            
        regex_pattern = param_regex.replace_all(&regex_pattern, r"(?P<$1>[^/]+)").to_string();
        
        // Add ^ and $ anchors to match the entire path
        regex_pattern = format!("^{}$", regex_pattern);
        
        Ok(regex_pattern)
    }
    
    // Parse a path into resource information
    pub fn parse_path(&self, path: &str) -> Result<ResourcePath, ResourceMappingError> {
        // Remove API prefix if present
        let clean_path = path.trim_start_matches("/api/v1").trim_start_matches('/');
        
        // Try to match the path against our patterns
        let matches = self.pattern_set.matches(clean_path);
        
        if !matches.matched_any() {
            debug!("No pattern matched path: {}", clean_path);
            
            // Fall back to the default path parsing
            return self.default_parse_path(clean_path);
        }
        
        // Find the first match
        let pattern_index = matches.iter().next().unwrap();
        let pattern = &self.patterns[pattern_index];
        
        // Get the regex captures
        let captures = pattern.regex.captures(clean_path)
            .ok_or_else(|| ResourceMappingError::PatternMatchFailed(
                format!("Failed to capture groups from path: {}", clean_path)
            ))?;
            
        // Extract resource type (always present)
        let resource_type = pattern.resource_type.clone();
        
        // Extract resource ID if present in the pattern
        let resource_id = pattern.resource_id_group.as_ref().and_then(|group| {
            captures.name(group).map(|m| m.as_str().to_string())
        });
        
        // Extract parent type if present in the pattern
        let parent_type = pattern.parent_type.clone();
        
        // Extract parent ID if present in the pattern
        let parent_id = pattern.parent_id_group.as_ref().and_then(|group| {
            captures.name(group).map(|m| m.as_str().to_string())
        });
        
        // Extract additional parameters
        let mut parameters = HashMap::new();
        for (param_name, group_name) in &pattern.parameter_groups {
            if let Some(capture) = captures.name(group_name) {
                parameters.insert(param_name.clone(), capture.as_str().to_string());
            }
        }
        
        Ok(ResourcePath {
            resource_type,
            resource_id,
            parent_type,
            parent_id,
            parameters,
        })
    }
    
    // Default path parsing logic for backward compatibility
    fn default_parse_path(&self, path: &str) -> Result<ResourcePath, ResourceMappingError> {
        // Split the path into segments
        let segments: Vec<&str> = path.split('/').collect();
        
        match segments.len() {
            // /resources
            1 => {
                Ok(ResourcePath {
                    resource_type: segments[0].to_string(),
                    resource_id: None,
                    parent_type: None,
                    parent_id: None,
                    parameters: HashMap::new(),
                })
            },
            // /resources/{id}
            2 => {
                Ok(ResourcePath {
                    resource_type: segments[0].to_string(),
                    resource_id: Some(segments[1].to_string()),
                    parent_type: None,
                    parent_id: None,
                    parameters: HashMap::new(),
                })
            },
            // /resources/{id}/subresources
            3 => {
                Ok(ResourcePath {
                    resource_type: segments[2].to_string(),
                    resource_id: None,
                    parent_type: Some(segments[0].to_string()),
                    parent_id: Some(segments[1].to_string()),
                    parameters: HashMap::new(),
                })
            },
            // /resources/{id}/subresources/{sub_id}
            4 => {
                Ok(ResourcePath {
                    resource_type: segments[2].to_string(),
                    resource_id: Some(segments[3].to_string()),
                    parent_type: Some(segments[0].to_string()),
                    parent_id: Some(segments[1].to_string()),
                    parameters: HashMap::new(),
                })
            },
            // Default or more complex paths
            _ => {
                Err(ResourceMappingError::InvalidPathFormat(
                    format!("Path format not supported: {}", path)
                ))
            }
        }
    }
    
    // Map HTTP method to Cedar action based on resource info and custom mappings
    pub fn map_method_to_action(&self, method: &str, path: &str, resource_info: &ResourcePath) -> String {
        // Check if we have a custom action mapping for this path
        for (pattern, action_map) in &self.custom_action_maps {
            if pattern.is_match(path) {
                if let Some(action) = action_map.get(&method.to_uppercase()) {
                    return format!("Action::\"{}\"", action);
                }
            }
        }
        
        // Use the default action mapping
        let base_action = self.default_action_map
            .get(&method.to_uppercase().to_string())
            .cloned()
            .unwrap_or_else(|| "access".to_string());
            
        // If it's a collection resource (no ID), adjust the action accordingly
        let action = match (&resource_info.resource_id, base_action.as_str()) {
            (None, "read") => "list",
            (None, "update") => "update_bulk",
            (None, "delete") => "delete_bulk",
            _ => &base_action,
        };
        
        format!("Action::\"{}\"", action)
    }

    // Create a Cedar context from HTTP request information
    pub fn create_request_context(
        &self,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        headers: &HashMap<String, String>,
    ) -> Context {
        let mut context_pairs = HashMap::new();
        
        // Add HTTP method
        context_pairs.insert("http_method".to_string(), method.to_string());
        
        // Add path
        context_pairs.insert("http_path".to_string(), path.to_string());
        
        // Add query parameters with prefix
        for (k, v) in query_params {
            context_pairs.insert(format!("query_{}", k), v.clone());
        }
        
        // Add selected headers (be careful not to include sensitive headers)
        let safe_headers = vec![
            "content-type", "accept", "accept-language", "x-request-id", 
            "user-agent", "referer", "origin"
        ];
        
        for header_name in safe_headers {
            if let Some(value) = headers.get(header_name) {
                context_pairs.insert(
                    format!("header_{}", header_name.replace('-', "_")), 
                    value.clone()
                );
            }
        }
        
        // Same approach - use from_json_str
        match serde_json::to_string(&context_pairs) {
            Ok(json_str) => match Context::from_json_str(&json_str, None) {
                Ok(context) => context,
                Err(_) => Context::empty(),
            },
            Err(_) => Context::empty(),
        }
    }
}

// Default configuration for ResourceMapper
pub fn create_default_resource_mapper() -> ResourceMapper {
    let mut mapper = ResourceMapper::new();
    
    // Add common REST API patterns
    let patterns = [
        // Basic collection/item pattern
        ("/api/v1/{resource}", "resource", Some("resource"), None, None, HashMap::new()),
        ("/api/v1/{resource}/{id}", "resource", Some("resource"), Some("id"), None, HashMap::new()),
        
        // Nested resources
        ("/api/v1/{parent}/{parentId}/{resource}", "resource", Some("resource"), 
            Some("parent"), Some("parentId"), HashMap::new()),
        ("/api/v1/{parent}/{parentId}/{resource}/{id}", "resource", Some("resource"), 
            Some("parent"), Some("parentId"), {
                let mut params = HashMap::new();
                params.insert("id", "id");
                params
            }),
            
        // User-specific resources
        ("/api/v1/users/{userId}/{resource}", "resource", Some("resource"), 
            Some("User"), Some("userId"), HashMap::new()),
        ("/api/v1/users/{userId}/{resource}/{id}", "resource", Some("resource"), 
            Some("User"), Some("userId"), {
                let mut params = HashMap::new();
                params.insert("id", "id");
                params
            }),
    ];
    
    // Add each pattern
    for (pattern, resource_type, resource_id_group, parent_type, parent_id_group, params) in patterns {
        mapper.add_pattern(
            pattern, 
            resource_type, 
            resource_id_group, 
            parent_type, 
            parent_id_group, 
            params,
        ).unwrap();
    }
    
    // Add custom action mappings
    let custom_mappings = [
        // Example: Special endpoints for batch operations
        ("/api/v1/{resource}/batch", {
            let mut map = HashMap::new();
            map.insert("POST", "batch_create");
            map.insert("PUT", "batch_update");
            map.insert("DELETE", "batch_delete");
            map
        }),
        
        // Example: Custom actions using POST with action in path
        ("/api/v1/{resource}/{id}/publish", {
            let mut map = HashMap::new();
            map.insert("POST", "publish");
            map
        }),
        ("/api/v1/{resource}/{id}/unpublish", {
            let mut map = HashMap::new();
            map.insert("POST", "unpublish");
            map
        }),
        ("/api/v1/{resource}/{id}/archive", {
            let mut map = HashMap::new();
            map.insert("POST", "archive");
            map
        }),
    ];
    
    // Add each custom mapping
    for (pattern, action_map) in custom_mappings {
        mapper.add_custom_action_mapping(pattern, action_map).unwrap();
    }
    
    mapper
}