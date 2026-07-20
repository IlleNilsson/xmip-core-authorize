#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use xmip_party::Party;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    pub action: String,
    pub resource: String,
    pub context: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub reason: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizeError {
    pub message: String,
}

impl fmt::Display for AuthorizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.message) }
}
impl Error for AuthorizeError {}

pub trait Authorizer: Send + Sync {
    fn authorize(
        &self,
        party: &Party,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationDecision, AuthorizeError>;
}
