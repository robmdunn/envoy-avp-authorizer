use std::collections::HashMap;
use cedar_policy::{Context};
use tracing::{debug, info, trace, warn};
use regex::{Regex, RegexSet};
use thiserror::Error;
use std::str::FromStr;
use std::fmt;

// Helper enum to identify explicit capture group references
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Literal(String),
    CaptureGroup(String),
}

impl FromStr for FieldValue {
    type Err = ResourceMappingError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check if the value is a capture group reference (surrounded by curly braces)
        if s.starts_with("{") && s.ends_with("}") {
            let capture_name = &s[1..s.len()-1];
            Ok(FieldValue::CaptureGroup(capture_name.to_string()))
        } else {
            Ok(FieldValue::Literal(s.to_string()))
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldValue::Literal(s) => write!(f, "{}", s),
            FieldValue::CaptureGroup(s) => write!(f, "{{{}}}", s),
        }
    }
}

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
        let result = match (&self.resource_id, &self.parent_type, &self.parent_id) {
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
        };
        debug!("Converted ResourcePath to entity_uid: '{}'", result);
        result
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
    resource_type: FieldValue,
    resource_id_group: Option<String>,
    parent_type: Option<FieldValue>,
    parent_id_group: Option<String>,
    parameter_groups: HashMap<String, String>,
}

// ResourceMapper maps HTTP paths to Cedar resources
pub struct ResourceMapper {
    patterns: Vec<ResourcePattern>,
    pattern_set: RegexSet,
    default_action_map: HashMap<String, String>,
    custom_action_maps: Vec<(Regex, HashMap<String, String>)>,
    api_prefix_regex: Regex,
}

impl ResourceMapper {
    pub fn new(api_prefix_pattern: &str) -> Self {
        let patterns = Vec::new();
        let pattern_set = RegexSet::new([""]).unwrap(); // Dummy set, will be replaced
        
        // Convert wildcard pattern to regex (e.g., "/api/v*/" -> "^/api/v[^/]*/")
        let api_prefix_regex_str = api_prefix_pattern
            .replace("*", "[^/]*")
            .replace("/", "\\/");
        
        let api_prefix_regex = Regex::new(&format!("^{}", api_prefix_regex_str))
            .unwrap_or_else(|_| Regex::new("^/api/v[^/]*/").unwrap());
        
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
            api_prefix_regex,
        }
    }
    
    pub fn get_patterns(&self) -> &[ResourcePattern] {
        &self.patterns
    }
    
    pub fn get_pattern_count(&self) -> usize {
        self.patterns.len()
    }
    
    // Pattern information helper method
    pub fn get_patterns_info(&self) -> Vec<String> {
        self.patterns.iter()
            .map(|p| format!("'{}' -> type: '{}', id_group: {:?}, parent: {:?}/{:?}", 
                            p.pattern, p.resource_type, p.resource_id_group, 
                            p.parent_type.as_ref().map(|pt| pt.to_string()), p.parent_id_group))
            .collect()
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
        
        // Parse resource_type as FieldValue
        let resource_type_value = FieldValue::from_str(resource_type)?;
            
        // Parse parent_type as FieldValue if provided
        let parent_type_value = if let Some(pt) = parent_type {
            Some(FieldValue::from_str(pt)?)
        } else {
            None
        };
            
        // Add the pattern
        self.patterns.push(ResourcePattern {
            pattern: pattern.to_string(),
            regex,
            resource_type: resource_type_value,
            resource_id_group: resource_id_group.map(ToString::to_string),
            parent_type: parent_type_value,
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
        // Add debug logging about the original path
        debug!("Attempting to parse path: '{}'", path);
        
        // Remove API prefix if present using regex
        let clean_path = if let Some(captures) = self.api_prefix_regex.captures(path) {
            let matched_prefix = captures.get(0).map_or("", |m| m.as_str());
            debug!("Found API prefix: '{}' in path", matched_prefix);
            path.strip_prefix(matched_prefix).unwrap_or(path)
        } else {
            path.trim_start_matches('/')
        };
        
        // Log if we modified the path
        if clean_path != path {
            debug!("Trimmed API prefix: '{}' -> '{}'", path, clean_path);
        }
        
        // Try to match the path against our patterns
        let matches = self.pattern_set.matches(clean_path);
        
        if !matches.matched_any() {
            debug!("No pattern matched path: '{}' (cleaned: '{}')", path, clean_path);
            debug!("Available patterns: {:?}", self.get_patterns_info());
            
            // Fall back to the default path parsing
            debug!("Falling back to default path parsing");
            return self.default_parse_path(clean_path);
        }
        
        // Find all matches for debugging
        let match_indices: Vec<_> = matches.iter().collect();
        debug!("Patterns matched for '{}': {:?} (using first match)", 
            clean_path, 
            match_indices.iter()
                .map(|&i| format!("{} ({})", i, self.patterns[i].pattern))
                .collect::<Vec<_>>());
        
        // Use the first match
        let pattern_index = match_indices[0];
        let pattern = &self.patterns[pattern_index];
        
        debug!("Path '{}' matched pattern '{}'", clean_path, pattern.pattern);
        
        // Get the regex captures
        let captures = pattern.regex.captures(clean_path)
            .ok_or_else(|| ResourceMappingError::PatternMatchFailed(
                format!("Failed to capture groups from path: {}", clean_path)
            ))?;
            
        // Extract resource type (always present)
        let resource_type = match &pattern.resource_type {
            FieldValue::Literal(literal_value) => literal_value.clone(),
            FieldValue::CaptureGroup(capture_name) => {
                // Use the captured value from the URL
                captures.name(capture_name)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| {
                        debug!("Capture group '{}' not found, using empty string", capture_name);
                        String::new()
                    })
            }
        };
        
        // Extract resource ID if present in the pattern
        let resource_id = if pattern.resource_id_group.as_ref().map_or(false, |g| g == "resource") && 
                        captures.name("id").is_some() {
            // Special case for {parent}/{parentId}/{resource}/{id} pattern
            // Use the "id" group as the resource ID instead of the "resource" group
            captures.name("id").map(|m| m.as_str().to_string())
        } else {
            pattern.resource_id_group.as_ref().and_then(|group| {
                let id = captures.name(group).map(|m| m.as_str().to_string());
                debug!("Extracted resource_id: {:?} from group: {:?}", id, group);
                id
            })
        };
        
        // Extract parent type if present in the pattern
        let parent_type = match &pattern.parent_type {
            Some(FieldValue::Literal(literal_value)) => Some(literal_value.clone()),
            Some(FieldValue::CaptureGroup(capture_name)) => {
                // Use the captured value from the URL
                captures.name(capture_name)
                    .map(|m| m.as_str().to_string())
            },
            None => None,
        };
        
        // Extract parent ID if present in the pattern
        let parent_id = pattern.parent_id_group.as_ref().and_then(|group| {
            let id = captures.name(group).map(|m| m.as_str().to_string());
            debug!("Extracted parent_id: {:?} from group: {:?}", id, group);
            id
        });
        
        // Extract additional parameters
        let mut parameters = HashMap::new();
        for (param_name, group_name) in &pattern.parameter_groups {
            if let Some(capture) = captures.name(group_name) {
                let value = capture.as_str().to_string();
                trace!("Extracted parameter: {}={} from group: {}", param_name, value, group_name);
                parameters.insert(param_name.clone(), value);
            } else {
                debug!("Failed to extract parameter: {} from group: {}", param_name, group_name);
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
        debug!("Mapping method '{}' to action for path '{}'", method, path);
        
        // Check if we have a custom action mapping for this path
        for (pattern, action_map) in &self.custom_action_maps {
            if pattern.is_match(path) {
                debug!("Path '{}' matched custom action pattern", path);
                if let Some(action) = action_map.get(&method.to_uppercase()) {
                    debug!("Mapped method '{}' to custom action '{}'", method, action);
                    return format!("Action::\"{}\"", action);
                }
            }
        }
        
        // Use the default action mapping
        let base_action = self.default_action_map
            .get(&method.to_uppercase().to_string())
            .cloned()
            .unwrap_or_else(|| {
                debug!("No mapping found for method '{}', using default 'access'", method);
                "access".to_string()
            });
            
        // If it's a collection resource (no ID), adjust the action accordingly
        let action = match (&resource_info.resource_id, base_action.as_str()) {
            (None, "read") => {
                debug!("Adjusted action from 'read' to 'list' for collection resource");
                "list"
            },
            (None, "update") => {
                debug!("Adjusted action from 'update' to 'update_bulk' for collection resource");
                "update_bulk"
            },
            (None, "delete") => {
                debug!("Adjusted action from 'delete' to 'delete_bulk' for collection resource");
                "delete_bulk"
            },
            _ => &base_action,
        };
        
        debug!("Final mapped action: '{}' for method '{}' on path '{}'", action, method, path);
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
pub fn create_default_resource_mapper(api_prefix_pattern: &str) -> ResourceMapper {
    info!("Creating default resource mapper with API prefix pattern: {}", 
        api_prefix_pattern);

    let mut mapper = ResourceMapper::new(api_prefix_pattern);
    
    debug!("Using default patterns without API prefix for resource mappings");
    
    // Add common REST API patterns WITHOUT the prefix using the explicit capture syntax
    let patterns = [
        // Basic collection/item pattern
        ("{resource}", "{resource}", Some("resource"), None, None, HashMap::new()),
        ("{resource}/{id}", "{resource}", Some("id"), None, None, HashMap::new()),
            
        // User-specific resources
        ("users/{userId}/{resource}", "{resource}", Some("resource"), 
            Some("User"), Some("userId"), HashMap::new()),
        ("users/{userId}/{resource}/{id}", "{resource}", Some("id"), 
            Some("User"), Some("userId"), HashMap::new()),

        // Nested resources
        ("{parent}/{parentId}/{resource}", "{resource}", Some("resource"), 
            Some("{parent}"), Some("parentId"), HashMap::new()),
        ("{parent}/{parentId}/{resource}/{id}", "{resource}", Some("id"), 
            Some("{parent}"), Some("parentId"), HashMap::new()),
    ];
    
    // Add each pattern
    for (pattern, resource_type, resource_id_group, parent_type, parent_id_group, params) in patterns {
        debug!("Adding default pattern: '{}'", pattern);
        
        if let Err(e) = mapper.add_pattern(
            pattern, 
            resource_type, 
            resource_id_group, 
            parent_type, 
            parent_id_group, 
            params,
        ) {
            warn!("Failed to add default pattern '{}': {}", pattern, e);
        }
    }
    
    // Add custom action mappings with the configurable prefix
    let custom_mappings = [
        // Example: Special endpoints for batch operations
        ("{resource}/batch", {
            let mut map = HashMap::new();
            map.insert("POST", "batch_create");
            map.insert("PUT", "batch_update");
            map.insert("DELETE", "batch_delete");
            map
        }),
        
        // Example: Custom actions using POST with action in path
        ("{resource}/{id}/publish", {
            let mut map = HashMap::new();
            map.insert("POST", "publish");
            map
        }),
        ("{resource}/{id}/unpublish", {
            let mut map = HashMap::new();
            map.insert("POST", "unpublish");
            map
        }),
        ("{resource}/{id}/archive", {
            let mut map = HashMap::new();
            map.insert("POST", "archive");
            map
        }),
    ];
    
    // Add each custom mapping
    for (pattern, action_map) in custom_mappings {
        debug!("Adding default action mapping for pattern: '{}'", pattern);
        
        if let Err(e) = mapper.add_custom_action_mapping(pattern, action_map) {
            warn!("Failed to add default action mapping for '{}': {}", pattern, e);
        }
    }
    
    mapper
}