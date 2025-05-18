use aws_sdk_verifiedpermissions::types::Decision as AwsDecision;

// Simple cache-compatible wrapper for AWS response
#[derive(Debug)]
pub struct CedarResponse {
    decision: AwsDecision,
    diagnostics: CedarDiagnostics,
}

impl CedarResponse {
    pub fn new(decision: AwsDecision, diagnostics: CedarDiagnostics) -> Self {
        Self {
            decision,
            diagnostics,
        }
    }
    
    pub fn decision(&self) -> &AwsDecision {
        &self.decision
    }
    
    pub fn diagnostics(&self) -> &CedarDiagnostics {
        &self.diagnostics
    }
}

#[derive(Debug)]
pub struct CedarDiagnostics {
    errors: Vec<String>,
}

impl CedarDiagnostics {
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
        }
    }
    
    pub fn with_errors(errors: Vec<String>) -> Self {
        Self {
            errors,
        }
    }
    
    pub fn errors(&self) -> std::slice::Iter<'_, String> {
        self.errors.iter()
    }
}