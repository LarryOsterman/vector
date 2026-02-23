use std::sync::Arc;

use azure_storage_blob::BlobContainerClient;
use tower::ServiceBuilder;
use url::Url;
use vector_lib::{
    codecs::{JsonSerializerConfig, NewlineDelimitedEncoderConfig, encoding::Framer},
    configurable::configurable_component,
    sensitive_string::SensitiveString,
};

use super::request_builder::AzureBlobRequestOptions;
use crate::{
    Result,
    codecs::{Encoder, EncodingConfigWithFraming, SinkType},
    config::{AcknowledgementsConfig, DataType, GenerateConfig, Input, SinkConfig, SinkContext},
    sinks::{
        Healthcheck, VectorSink,
        azure_common::{
            self, config::AzureBlobRetryLogic, service::AzureBlobService, sink::AzureBlobSink,
        },
        util::{
            BatchConfig, BulkSizeBasedDefaultBatchSettings, Compression, ServiceBuilderExt,
            TowerRequestConfig, partitioner::KeyPartitioner, service::TowerRequestConfigDefaults,
        },
    },
    template::Template,
};

#[derive(Clone, Copy, Debug)]
pub struct AzureBlobTowerRequestConfigDefaults;

impl TowerRequestConfigDefaults for AzureBlobTowerRequestConfigDefaults {
    const RATE_LIMIT_NUM: u64 = 250;
}

/// Authorization methods for the Azure Blob Storage sink.
///
#[configurable_component]
#[derive(Clone, Debug)]
pub enum AzureBlobSinkAuthorization {
    /// The Azure Blob Storage Account connection string.
    ///
    /// Authentication with an access key or shared access signature (SAS)
    /// are supported authentication methods. If using a non-account SAS,
    /// healthchecks will fail and will need to be disabled by setting
    /// `healthcheck.enabled` to `false` for this sink
    ///
    /// When generating an account SAS, the following are the minimum required option
    /// settings for Vector to access blob storage and pass a health check.
    /// | Option                 | Value              |
    /// | ---------------------- | ------------------ |
    /// | Allowed services       | Blob               |
    /// | Allowed resource types | Container & Object |
    /// | Allowed permissions    | Read & Create      |
    ///
    /// Use a connection string for authentication. The connection string can be provided in the `connection_string` field of the sink configuration.
    ///
    /// ** SECURITY NOTE **
    /// Connection strings contain sensitive information, such as access keys or SAS tokens, that can be used to gain unauthorized access to your Azure Blob Storage resources.
    /// It is important to keep connection strings secure and not expose them in logs, error messages, or version control systems.
    ///
    /// Numerous security breaches have occurred due to leaked connection strings,
    /// so please take care to manage them securely. Consider using secret management tools to store and manage connection strings securely.
    ConnectionString(SensitiveString),

    /// Use Azure AD Workload Identity for authentication. This method is typically used when Vector is running in an Azure environment that supports workload identity, such as Azure Kubernetes Service (AKS) with workload identity enabled.
    WorkloadIdentityCredential,

    /// Use Managed Identity Credential for authentication. This method is typically used when Vector is running in an Azure environment that supports managed identities, such as Azure Virtual Machines or Azure App Service.
    ManagedIdentityCredential,

    /// Use Azure Pipeline Credential for authentication. This method is typically used in Azure DevOps pipelines where the pipeline has been granted access to the Azure Blob Storage resources.
    AzurePipelineCredential,

    /// Use Developer Tools Credential for authentication. This method is typically used for local development and testing, allowing developers to authenticate using their Azure developer tools credentials.
    DeveloperToolsCredential,
}

/// Configuration for the `azure_blob` sink.
#[configurable_component(sink(
    "azure_blob",
    "Store your observability data in Azure Blob Storage."
))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AzureBlobSinkConfig {
    /// The Azure Blob Storage Account connection string.
    ///
    /// Authentication with an access key or shared access signature (SAS)
    /// are supported authentication methods. If using a non-account SAS,
    /// healthchecks will fail and will need to be disabled by setting
    /// `healthcheck.enabled` to `false` for this sink
    ///
    /// When generating an account SAS, the following are the minimum required option
    /// settings for Vector to access blob storage and pass a health check.
    /// | Option                 | Value              |
    /// | ---------------------- | ------------------ |
    /// | Allowed services       | Blob               |
    /// | Allowed resource types | Container & Object |
    /// | Allowed permissions    | Read & Create      |
    ///
    /// Note that connection string authentication is mutually exclusive with the `authorization` field, and will take precedence over any specified authorization method in the `authorization` field.
    /// If both a `connection_string` and an `authorization` method are provided, sink initialization will fail.
    /// If neither a `connection_string` nor an `authorization` method are provided, sink initialization will fail.
    ///
    /// # SECURITY NOTE
    /// Connection strings contain sensitive information, such as access keys or SAS
    /// tokens, that can be used to gain unauthorized access to your Azure Blob Storage
    /// resources. It is important to keep connection strings secure and not expose them
    /// in logs, error messages, or version control systems.
    ///
    /// Numerous security breaches have occurred due to leaked connection strings,
    /// so please take care to manage them securely. Consider using secret management
    /// tools to store and manage connection strings securely.
    ///
    #[configurable(metadata(
        docs::examples = "DefaultEndpointsProtocol=https;AccountName=mylogstorage;AccountKey=storageaccountkeybase64encoded;EndpointSuffix=core.windows.net"
    ))]
    #[configurable(metadata(
        docs::examples = "BlobEndpoint=https://mylogstorage.blob.core.windows.net/;SharedAccessSignature=generatedsastoken"
    ))]
    pub connection_string: Option<SensitiveString>,

    /// The authorization method to use when connecting to Azure Blob Storage.
    ///
    /// If not specified, Vector will attempt to determine the appropriate authentication method based on
    /// the provided `connection_string`. If a `connection_string` is not provided, Vector will attempt to
    /// authenticate using Azure AD Workload Identity, and if that fails, will fall back to Managed
    /// Identity Credential authentication.
    #[configurable]
    pub authorization: Option<AzureBlobSinkAuthorization>,

    /// The base URL for the Azure Blob Storage account. This is required when using authentication mechanisms other than ConnectionString,
    /// and is ignored when using `ConnectionString` authentication since the storage account is already specified in the connection string.
    #[configurable]
    pub storage_account: Option<Url>,

    /// The Azure Blob Storage Account container name.
    #[configurable(metadata(docs::examples = "my-logs"))]
    pub(super) container_name: String,

    /// A prefix to apply to all blob keys.
    ///
    /// Prefixes are useful for partitioning objects, such as by creating a blob key that
    /// stores blobs under a particular directory. If using a prefix for this purpose, it must end
    /// in `/` to act as a directory path. A trailing `/` is **not** automatically added.
    #[configurable(metadata(docs::examples = "date/%F/hour/%H/"))]
    #[configurable(metadata(docs::examples = "year=%Y/month=%m/day=%d/"))]
    #[configurable(metadata(
        docs::examples = "kubernetes/{{ metadata.cluster }}/{{ metadata.application_name }}/"
    ))]
    #[serde(default = "default_blob_prefix")]
    pub blob_prefix: Template,

    /// The timestamp format for the time component of the blob key.
    ///
    /// By default, blob keys are appended with a timestamp that reflects when the blob are sent to
    /// Azure Blob Storage, such that the resulting blob key is functionally equivalent to joining
    /// the blob prefix with the formatted timestamp, such as `date=2022-07-18/1658176486`.
    ///
    /// This would represent a `blob_prefix` set to `date=%F/` and the timestamp of Mon Jul 18 2022
    /// 20:34:44 GMT+0000, with the `filename_time_format` being set to `%s`, which renders
    /// timestamps in seconds since the Unix epoch.
    ///
    /// Supports the common [`strftime`][chrono_strftime_specifiers] specifiers found in most
    /// languages.
    ///
    /// When set to an empty string, no timestamp is appended to the blob prefix.
    ///
    /// [chrono_strftime_specifiers]: https://docs.rs/chrono/latest/chrono/format/strftime/index.html#specifiers
    #[configurable(metadata(docs::syntax_override = "strftime"))]
    pub blob_time_format: Option<String>,

    /// Whether or not to append a UUID v4 token to the end of the blob key.
    ///
    /// The UUID is appended to the timestamp portion of the object key, such that if the blob key
    /// generated is `date=2022-07-18/1658176486`, setting this field to `true` results
    /// in an blob key that looks like
    /// `date=2022-07-18/1658176486-30f6652c-71da-4f9f-800d-a1189c47c547`.
    ///
    /// This ensures there are no name collisions, and can be useful in high-volume workloads where
    /// blob keys must be unique.
    pub blob_append_uuid: Option<bool>,

    #[serde(flatten)]
    pub encoding: EncodingConfigWithFraming,

    /// Compression configuration.
    ///
    /// All compression algorithms use the default compression level unless otherwise specified.
    ///
    /// Some cloud storage API clients and browsers handle decompression transparently, so
    /// depending on how they are accessed, files may not always appear to be compressed.
    #[configurable(derived)]
    #[serde(default = "Compression::gzip_default")]
    pub compression: Compression,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<BulkSizeBasedDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig<AzureBlobTowerRequestConfigDefaults>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::is_default"
    )]
    pub(super) acknowledgements: AcknowledgementsConfig,

    /// Self-Signed TLS Server certificate for use when validating TLS connections to local servers (Azurite)
    #[cfg(test)]
    pub tls_server_certificate: Option<String>,
}

pub fn default_blob_prefix() -> Template {
    Template::try_from(DEFAULT_KEY_PREFIX).unwrap()
}

impl GenerateConfig for AzureBlobSinkConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(Self {
            connection_string: None,
            authorization: None,
            storage_account: None,
            container_name: String::from("logs"),
            blob_prefix: default_blob_prefix(),
            blob_time_format: Some(String::from("%s")),
            blob_append_uuid: Some(true),
            encoding: (
                Some(NewlineDelimitedEncoderConfig::new()),
                JsonSerializerConfig::default(),
            )
                .into(),
            compression: Compression::gzip_default(),
            batch: BatchConfig::default(),
            request: TowerRequestConfig::default(),
            acknowledgements: Default::default(),
            #[cfg(test)]
            tls_server_certificate: None,
        })
        .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "azure_blob")]
impl SinkConfig for AzureBlobSinkConfig {
    async fn build(&self, cx: SinkContext) -> Result<(VectorSink, Healthcheck)> {
        if self.connection_string.is_none() && self.authorization.is_none() {
            return Err(
                "Either a connection string or an authorization method must be provided".into(),
            );
        } else if self.connection_string.is_some() && self.authorization.is_some() {
            return Err(
            "Both connection string and authorization method cannot be provided at the same time"
                .into(),
            );
        }
        let authorization = if self.connection_string.is_some() {
            AzureBlobSinkAuthorization::ConnectionString(self.connection_string.clone().unwrap())
        } else {
            self.authorization.clone().unwrap()
        };

        let client = azure_common::config::build_client(
            authorization,
            self.storage_account.clone(),
            &self.container_name,
            cx.proxy(),
            #[cfg(test)]
            self.tls_server_certificate.clone(),
        )?;

        let healthcheck = azure_common::config::build_healthcheck(
            self.container_name.clone(),
            Arc::clone(&client),
        )?;
        let sink = self.build_processor(client)?;
        Ok((sink, healthcheck))
    }

    fn input(&self) -> Input {
        Input::new(self.encoding.config().1.input_type() & DataType::Log)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

const DEFAULT_KEY_PREFIX: &str = "blob/%F/";
const DEFAULT_FILENAME_TIME_FORMAT: &str = "%s";
const DEFAULT_FILENAME_APPEND_UUID: bool = true;

impl AzureBlobSinkConfig {
    pub fn build_processor(&self, client: Arc<BlobContainerClient>) -> crate::Result<VectorSink> {
        let request_limits = self.request.into_settings();
        let service = ServiceBuilder::new()
            .settings(request_limits, AzureBlobRetryLogic)
            .service(AzureBlobService::new(client));

        // Configure our partitioning/batching.
        let batcher_settings = self.batch.into_batcher_settings()?;

        let blob_time_format = self
            .blob_time_format
            .as_ref()
            .cloned()
            .unwrap_or_else(|| DEFAULT_FILENAME_TIME_FORMAT.into());
        let blob_append_uuid = self
            .blob_append_uuid
            .unwrap_or(DEFAULT_FILENAME_APPEND_UUID);

        let transformer = self.encoding.transformer();
        let (framer, serializer) = self.encoding.build(SinkType::MessageBased)?;
        let encoder = Encoder::<Framer>::new(framer, serializer);

        let request_options = AzureBlobRequestOptions {
            container_name: self.container_name.clone(),
            blob_time_format,
            blob_append_uuid,
            encoder: (transformer, encoder),
            compression: self.compression,
        };

        let sink = AzureBlobSink::new(
            service,
            request_options,
            self.key_partitioner()?,
            batcher_settings,
        );

        Ok(VectorSink::from_event_streamsink(sink))
    }

    pub fn key_partitioner(&self) -> crate::Result<KeyPartitioner> {
        Ok(KeyPartitioner::new(self.blob_prefix.clone(), None))
    }
}
