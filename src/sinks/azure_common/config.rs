use std::sync::Arc;

use azure_core::error::Error as AzureCoreError;

use crate::sinks::azure_blob::AzureBlobSinkAuthorization;
use crate::sinks::azure_common::connection_string::{Auth, ParsedConnectionString};
use crate::sinks::azure_common::shared_key_policy::SharedKeyAuthorizationPolicy;

use azure_core::{credentials::TokenCredential, http::Url};
use azure_identity::DeveloperToolsCredential;
use azure_storage_blob::{BlobContainerClient, BlobContainerClientOptions};

use azure_core::http::StatusCode;
use bytes::Bytes;
use futures::FutureExt;
use snafu::Snafu;
use vector_lib::{
    json_size::JsonSize,
    request_metadata::{GroupedCountByteSize, MetaDescriptive, RequestMetadata},
    stream::DriverResponse,
};

use crate::{
    event::{EventFinalizers, EventStatus, Finalizable},
    sinks::{Healthcheck, util::retries::RetryLogic},
};

#[derive(Debug, Clone)]
pub struct AzureBlobRequest {
    pub blob_data: Bytes,
    pub content_encoding: Option<&'static str>,
    pub content_type: &'static str,
    pub metadata: AzureBlobMetadata,
    pub request_metadata: RequestMetadata,
}

impl Finalizable for AzureBlobRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        std::mem::take(&mut self.metadata.finalizers)
    }
}

impl MetaDescriptive for AzureBlobRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.request_metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.request_metadata
    }
}

#[derive(Clone, Debug)]
pub struct AzureBlobMetadata {
    pub partition_key: String,
    pub count: usize,
    pub byte_size: JsonSize,
    pub finalizers: EventFinalizers,
}

#[derive(Debug, Clone)]
pub struct AzureBlobRetryLogic;

impl RetryLogic for AzureBlobRetryLogic {
    type Error = AzureCoreError;
    type Request = AzureBlobRequest;
    type Response = AzureBlobResponse;

    fn is_retriable_error(&self, error: &Self::Error) -> bool {
        match error.http_status() {
            Some(code) => code.is_server_error() || code == StatusCode::TooManyRequests,
            None => false,
        }
    }
}

#[derive(Debug)]
pub struct AzureBlobResponse {
    pub events_byte_size: GroupedCountByteSize,
    pub byte_size: usize,
}

impl DriverResponse for AzureBlobResponse {
    fn event_status(&self) -> EventStatus {
        EventStatus::Delivered
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        &self.events_byte_size
    }

    fn bytes_sent(&self) -> Option<usize> {
        Some(self.byte_size)
    }
}

#[derive(Debug, Snafu)]
pub enum HealthcheckError {
    #[snafu(display("Invalid connection string specified"))]
    InvalidCredentials,
    #[snafu(display("Container: {:?} not found", container))]
    UnknownContainer { container: String },
    #[snafu(display("Unknown status code: {}", status))]
    Unknown { status: StatusCode },
}

pub fn build_healthcheck(
    container_name: String,
    client: Arc<BlobContainerClient>,
) -> crate::Result<Healthcheck> {
    let healthcheck = async move {
        let resp: crate::Result<()> = match client.get_properties(None).await {
            Ok(_) => Ok(()),
            Err(error) => {
                let code = error.http_status();
                Err(match code {
                    Some(StatusCode::Forbidden) => Box::new(HealthcheckError::InvalidCredentials),
                    Some(StatusCode::NotFound) => Box::new(HealthcheckError::UnknownContainer {
                        container: container_name,
                    }),
                    Some(status) => Box::new(HealthcheckError::Unknown { status }),
                    None => "unknown status code".into(),
                })
            }
        };
        resp
    };

    Ok(healthcheck.boxed())
}

fn process_connection_string(
    connection_string: &str,
    container_name: &str,
) -> crate::Result<(
    Url,
    Option<Arc<dyn TokenCredential>>,
    Option<SharedKeyAuthorizationPolicy>,
)> {
    let parsed = ParsedConnectionString::parse(connection_string)
        .map_err(|e| format!("Invalid connection string: {e}"))?;
    let container_url = parsed
        .container_url(container_name)
        .map_err(|e| format!("Failed to build container URL: {e}"))?;
    let url = Url::parse(&container_url).map_err(|e| format!("Invalid container URL: {e}"))?;

    let auth_policy = match parsed.auth() {
        Auth::Sas { .. } | Auth::None => None,
        Auth::SharedKey {
            account_name,
            account_key,
        } => Some(SharedKeyAuthorizationPolicy::new(
            account_name,
            account_key,
            String::from("2025-11-05"),
        )?),
    };

    Ok((url, None, auth_policy))
}

pub fn build_client(
    authorization: AzureBlobSinkAuthorization,
    account_url: Option<Url>,
    container_name: &str,
    proxy: &crate::config::ProxyConfig,
    #[cfg(test)] tls_server_certificate: Option<String>,
) -> crate::Result<Arc<BlobContainerClient>> {
    // Parse connection string without legacy SDK
    let (url, token_credential, shared_key_policy) = match authorization {
        AzureBlobSinkAuthorization::ConnectionString(connection_string) => {
            // Process the connection string, decompose into Url and optional Shared Key policy (no token_credential).
            process_connection_string(connection_string.inner(), container_name)?
        }
        AzureBlobSinkAuthorization::DeveloperToolsCredential => {
            // Use Azure Identity's Developer Tools Credential for authentication.
            // This credential supports various developer tools authentication methods, such as Azure CLI, Visual Studio Code, and Azure PowerShell.
            let token_credential: Arc<dyn TokenCredential> = DeveloperToolsCredential::new(None)
                .map_err(|e| format!("Failed to create Developer Tools Credential: {e}"))?;
            let Some(mut account_url) = account_url else {
                return Err(
                    "Storage account must be provided when using managed identity authentication"
                        .into(),
                );
            };
            {
                let mut path_segments = account_url.path_segments_mut().map_err(|_| {
                    "Invalid account URL: missing path segments for container name".to_string()
                })?;
                path_segments.extend([container_name]);
            }
            (account_url, Some(token_credential), None)
        }
        _ => {
            return Err("Unsupported authorization method".into());
        }
    };

    // Prepare options; attach Shared Key policy if needed
    let mut options = BlobContainerClientOptions::default();
    options.client_options.user_agent.application_id = Some("VectorAzureBlobSink".to_string());
    if let Some(shared_key_policy) = shared_key_policy {
        options
            .client_options
            .per_call_policies
            .push(Arc::new(shared_key_policy));
    }

    // Use reqwest v0.13 since Azure SDK only implements HttpClient for reqwest::Client v0.13
    let mut reqwest_builder = reqwest_13::ClientBuilder::new();
    let bypass_proxy = {
        let host = url.host_str().unwrap_or("");
        let port = url.port();
        proxy.no_proxy.matches(host)
            || port
                .map(|p| proxy.no_proxy.matches(&format!("{}:{}", host, p)))
                .unwrap_or(false)
    };
    if bypass_proxy || !proxy.enabled {
        // Ensure no proxy (and disable any potential system proxy auto-detection)
        reqwest_builder = reqwest_builder.no_proxy();
    } else {
        if let Some(http) = &proxy.http {
            let p = reqwest_13::Proxy::http(http)
                .map_err(|e| format!("Invalid HTTP proxy URL: {e}"))?;
            // If credentials are embedded in the proxy URL, reqwest will handle them.
            reqwest_builder = reqwest_builder.proxy(p);
        }
        if let Some(https) = &proxy.https {
            let p = reqwest_13::Proxy::https(https)
                .map_err(|e| format!("Invalid HTTPS proxy URL: {e}"))?;
            // If credentials are embedded in the proxy URL, reqwest will handle them.
            reqwest_builder = reqwest_builder.proxy(p);
        }
    }

    #[cfg(test)]
    {
        reqwest_builder = if let Some(tls_server_certificate) = tls_server_certificate {
            reqwest_builder.add_root_certificate(
                reqwest_13::tls::Certificate::from_pem(tls_server_certificate.as_bytes())
                    .map_err(|e| format!("Failed to parse TLS server certificate: {e}"))?,
            )
        } else {
            reqwest_builder
        };
    }
    let transport = azure_core::http::Transport::new(std::sync::Arc::new(
        reqwest_builder
            .build()
            .map_err(|e| format!("Failed to build reqwest client: {e}"))?,
    ));
    options.client_options.transport = Some(transport);
    let client = BlobContainerClient::from_url(url, token_credential, Some(options))
        .map_err(|e| format!("{e}"))?;
    Ok(Arc::new(client))
}
