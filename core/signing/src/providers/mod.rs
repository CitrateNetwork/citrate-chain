//! Concrete signing-service backends. Each implements `crate::SigningProvider`.

pub mod docusign;

pub use docusign::DocusignProvider;
