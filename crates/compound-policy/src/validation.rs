use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ValidationFinding>,
}

impl ValidationReport {
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn push_error(&mut self, message: impl Into<String>) {
        self.findings.push(ValidationFinding {
            severity: Severity::Error,
            message: message.into(),
        });
    }

    pub fn push_warning(&mut self, message: impl Into<String>) {
        self.findings.push(ValidationFinding {
            severity: Severity::Warning,
            message: message.into(),
        });
    }

    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFinding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Error,
}
