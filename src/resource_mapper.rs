use std::collections::HashMap;
use tracing::{debug, info, trace, warn};
use regex::{Regex, RegexSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ResourceMappingError {
    #[error("Invalid path format: {0}")]
    InvalidPathFormat(String),
    
    #[error("Failed to match resource pattern: {0}")]
    PatternMatchFailed(String),
}

// ResourcePath stores the basic components of a resource
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePath {
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub parents: Vec<Parent>,
    pub parameters: HashMap<String, String>,
    pub matched_pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    pub parent_type: String,
    pub parent_id: String,
}

// A resource pattern for mapping paths to resources
#[derive(Debug, Clone)]
struct ResourcePattern {
    pattern: String,
    regex: Regex,
    resource_type: String,  // ← Simplified
    resource_id: Option<String>,
    parents: Vec<(String, String)>,
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
    
    pub fn get_pattern_count(&self) -> usize {
        self.patterns.len()
    }
    
    // Pattern information helper method
    pub fn get_patterns_info(&self) -> Vec<String> {
        self.patterns.iter()
            .map(|p| format!("'{}' -> type: '{}', resource_id: {:?}, parents: {:?}", 
                            p.pattern, p.resource_type, p.resource_id, p.parents))
            .collect()
    }

    // Add a resource pattern for mapping
    pub fn add_pattern(
        &mut self,
        pattern: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        parents: Vec<(String, String)>, // Vec of (parent_type, parent_id) pairs
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
        let resource_type_value = resource_type.to_string();
            
        // Convert parents vector to owned strings
        let parents_owned: Vec<(String, String)> = parents.into_iter().collect();
            
        // Add the pattern
        self.patterns.push(ResourcePattern {
            pattern: pattern.to_string(),
            regex,
            resource_type: resource_type_value,
            resource_id: resource_id.map(ToString::to_string),
            parents: parents_owned,
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
            .unwrap_or_else(|_| RegexSet::new([""]).unwrap());
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
        trace!("Attempting to parse path: '{}'", path);
        
        // Remove API prefix if present using regex
        let clean_path = if let Some(captures) = self.api_prefix_regex.captures(path) {
            let matched_prefix = captures.get(0).map_or("", |m| m.as_str());
            trace!("Found API prefix: '{}' in path", matched_prefix);
            path.strip_prefix(matched_prefix).unwrap_or(path)
        } else {
            path.trim_start_matches('/')
        };
        
        // Log if we modified the path
        if clean_path != path {
            trace!("Trimmed API prefix: '{}' -> '{}'", path, clean_path);
        }
        
        // Try to match the path against our patterns
        let matches = self.pattern_set.matches(clean_path);
        
        if !matches.matched_any() {
            trace!("No pattern matched path: '{}' (cleaned: '{}')", path, clean_path);
            trace!("Available patterns: {:?}", self.get_patterns_info());
            
            // Fall back to the default path parsing
            trace!("Falling back to default path parsing");
            return self.default_parse_path(clean_path);
        }
        
        // Find all matches for debugging
        let match_indices: Vec<_> = matches.iter().collect();
        trace!("Patterns matched for '{}': {:?} (using first match)", 
            clean_path, 
            match_indices.iter()
                .map(|&i| format!("{} ({})", i, self.patterns[i].pattern))
                .collect::<Vec<_>>());
        
        // Use the first match
        let pattern_index = match_indices[0];
        let pattern = &self.patterns[pattern_index];
        
        trace!("Path '{}' matched pattern '{}'", clean_path, pattern.pattern);
        
        // Get the regex captures
        let captures = pattern.regex.captures(clean_path)
            .ok_or_else(|| ResourceMappingError::PatternMatchFailed(
                format!("Failed to capture groups from path: {}", clean_path)
            ))?;
            
        // Build capture map for substitution using named groups
        let mut capture_map = HashMap::new();
        for (i, name) in pattern.regex.capture_names().enumerate() {
            if let Some(group_name) = name {
                if let Some(matched) = captures.get(i) {
                    capture_map.insert(group_name.to_string(), matched.as_str().to_string());
                    trace!("Captured: {} = {}", group_name, matched.as_str());
                }
            }
        }

        // Extract resource type with substitution
        let resource_type = substitute_variables(&pattern.resource_type, &capture_map)
            .unwrap_or_else(|_| pattern.resource_type.clone());

        // Extract resource ID with substitution
        let resource_id = pattern.resource_id.as_ref().and_then(|template| {
            let substituted = substitute_variables(template, &capture_map)
                .unwrap_or_else(|_| template.clone());
            if substituted.is_empty() {
                None
            } else {
                Some(substituted)
            }
        });

        // Extract parents with substitution
        let mut parents = Vec::new();
        for (parent_type_template, parent_id_template) in &pattern.parents {
            let parent_type = substitute_variables(parent_type_template, &capture_map)
                .unwrap_or_else(|_| parent_type_template.clone());
            let parent_id = substitute_variables(parent_id_template, &capture_map)
                .unwrap_or_else(|_| parent_id_template.clone());
            
            if !parent_type.is_empty() && !parent_id.is_empty() {
                trace!("Adding parent: {} = {}", parent_type, parent_id);
                parents.push(Parent {
                    parent_type,
                    parent_id,
                });
            }
        }
        
        // Extract additional parameters
        let mut parameters = HashMap::new();
        for (param_name, group_name) in &pattern.parameter_groups {
            if let Some(capture) = captures.name(group_name) {
                let value = capture.as_str().to_string();
                trace!("Extracted parameter: {}={} from group: {}", param_name, value, group_name);
                parameters.insert(param_name.clone(), value);
            } else {
                trace!("Failed to extract parameter: {} from group: {}", param_name, group_name);
            }
        }
        
        let resource_path = ResourcePath {
            resource_type,
            resource_id,
            parents,
            parameters,
            matched_pattern: pattern.pattern.clone(),
        };

        // Consistent resource logging
        let resource_display = match &resource_path.resource_id {
            Some(id) => format!("{}::{}", resource_path.resource_type, id),
            None => resource_path.resource_type.clone(),
        };
        trace!("Parsed resource: {}", resource_display);

        if !resource_path.parents.is_empty() {
            for (i, parent) in resource_path.parents.iter().enumerate() {
                trace!("  parent[{}]: {}::{}", i, parent.parent_type, parent.parent_id);
            }
        }

        trace!("Resource parameters: {:?}", resource_path.parameters);

        Ok(resource_path)
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
                parents: Vec::new(),
                parameters: HashMap::new(),
                matched_pattern: format!("default:/{}", segments[0]),
            })
        },
        // /resources/{id}
        2 => {
            Ok(ResourcePath {
                resource_type: segments[0].to_string(),
                resource_id: Some(segments[1].to_string()),
                parents: Vec::new(),
                parameters: HashMap::new(),
                matched_pattern: format!("default:/{}/{{id}}", segments[0]),
            })
        },
        // /resources/{id}/subresources  
        3 => {
            Ok(ResourcePath {
                resource_type: segments[2].to_string(),
                resource_id: None,
                parents: vec![Parent {
                    parent_type: segments[0].to_string(),
                    parent_id: segments[1].to_string(),
                }],
                parameters: HashMap::new(),
                matched_pattern: format!("default:/{}/{{id}}/{}", segments[0], segments[2]),  // Add this
            })
        },
        // /resources/{id}/subresources/{sub_id}
        4 => {
            Ok(ResourcePath {
                resource_type: segments[2].to_string(),
                resource_id: Some(segments[3].to_string()),
                parents: vec![Parent {
                    parent_type: segments[0].to_string(),
                    parent_id: segments[1].to_string(),
                }],
                parameters: HashMap::new(),
                matched_pattern: format!("default:/{}/{{id}}/{}/{{id}}", segments[0], segments[2]),  // Add this
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
    pub fn map_method_to_action(&self, method: &str, path: &str, _resource_info: &ResourcePath) -> String {
        trace!("Mapping method '{}' to action for path '{}'", method, path);
        
        // Clean up the path by removing the API prefix if present
        let clean_path = if let Some(captures) = self.api_prefix_regex.captures(path) {
            let matched_prefix = captures.get(0).map_or("", |m| m.as_str());
            trace!("Removing API prefix: '{}' from path for action mapping", matched_prefix);
            path.strip_prefix(matched_prefix).unwrap_or(path)
        } else {
            path.trim_start_matches('/')
        };
        
        trace!("Using clean path for action mapping: '{}'", clean_path);
        
        // Check if we have a custom action mapping for this path
        for (pattern, action_map) in &self.custom_action_maps {
            if pattern.is_match(clean_path) {
                trace!("Path '{}' matched custom action pattern", clean_path);
                if let Some(action) = action_map.get(&method.to_uppercase()) {
                    trace!("Mapped method '{}' to custom action '{}'", method, action);
                    if action.contains("::") {
                        trace!("Using namespaced action as is: {}", action);
                        return action.clone();
                    } else {
                        trace!("Adding Action:: prefix to: {}", action);
                        return format!("Action::\"{}\"", action);
                    }
                }
            }
        }
        
        // Use the default action mapping
        let base_action = self.default_action_map
            .get(&method.to_uppercase().to_string())
            .cloned()
            .unwrap_or_else(|| {
                trace!("No mapping found for method '{}', using default 'access'", method);
                "access".to_string()
            });
            
        let action = &base_action;
        let formatted_action = format!("Action::\"{}\"", action);

        debug!("Mapped action: {} (method={}, path={})", formatted_action, method, clean_path);
        trace!("Action mapping details: method='{}' -> base_action='{}' -> formatted='{}'", method, action, formatted_action);

        formatted_action
    }
}

// Substitute ${variable} patterns in a string with values from capture groups
fn substitute_variables(template: &str, captures: &HashMap<String, String>) -> Result<String, ResourceMappingError> {
    let var_regex = Regex::new(r"\$\{([^}]+)\}")
        .map_err(|e| ResourceMappingError::InvalidPathFormat(format!("Invalid substitution regex: {}", e)))?;
    
    let mut result = template.to_string();
    
    for cap in var_regex.captures_iter(template) {
        let full_match = cap.get(0).unwrap().as_str(); // ${variable}
        let var_name = cap.get(1).unwrap().as_str();    // variable
        
        if let Some(value) = captures.get(var_name) {
            result = result.replace(full_match, value);
            trace!("Substituted ${{{}}}: '{}' -> '{}'", var_name, full_match, value);
        } else {
            trace!("Variable '{}' not found in captures, leaving as literal", var_name);
            // Don't treat missing variables as errors - just leave them as literals
        }
    }
    
    Ok(result)
}

// Default configuration for ResourceMapper
pub fn create_default_resource_mapper(api_prefix_pattern: &str) -> ResourceMapper {
    info!("Creating default resource mapper with API prefix pattern: {}", 
        api_prefix_pattern);

    let mut mapper = ResourceMapper::new(api_prefix_pattern);
    
    debug!("Using default patterns without API prefix for resource mappings");
    
    // Add common REST API patterns WITHOUT the prefix using the new substitution syntax
    let patterns = [
        // Basic collection/item pattern
        ("{resource}", "${resource}", None, Vec::new()),
        ("{resource}/{id}", "${resource}", Some("${id}"), Vec::new()),
            
        // User-specific resources
        ("users/{userId}/{resource}", "${resource}", None, 
            vec![("User".to_string(), "${userId}".to_string())]),
        ("users/{userId}/{resource}/{id}", "${resource}", Some("${id}"), 
            vec![("User".to_string(), "${userId}".to_string())]),

        // Nested resources
        ("{parent}/{parentId}/{resource}", "${resource}", None, 
            vec![("${parent}".to_string(), "${parentId}".to_string())]),
        ("{parent}/{parentId}/{resource}/{id}", "${resource}", Some("${id}"), 
            vec![("${parent}".to_string(), "${parentId}".to_string())]),
    ];

    // Add each pattern
    for (pattern, resource_type, resource_id, parents) in patterns {
        debug!("Adding default pattern: '{}'", pattern);
        
        if let Err(e) = mapper.add_pattern(
            pattern, 
            resource_type, 
            resource_id, 
            parents, 
            HashMap::new(), // Empty parameter_groups
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