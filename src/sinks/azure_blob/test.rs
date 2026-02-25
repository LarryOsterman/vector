use super::{config::AzureBlobSinkConfig, request_builder::AzureBlobRequestOptions};
use crate::{
    codecs::{Encoder, EncodingConfigWithFraming},
    event::{Event, LogEvent},
    sinks::{
        azure_blob::AzureBlobSinkAuthorization,
        util::{
            Compression,
            request_builder::{EncodeResult, RequestBuilder},
        },
    },
};
use bytes::Bytes;
use chrono::Utc;
use url::Url;
use vector_lib::{
    EstimatedJsonEncodedSizeOf,
    codecs::{
        NewlineDelimitedEncoder, TextSerializerConfig,
        encoding::{Framer, FramingConfig},
    },
    partition::Partitioner,
    request_metadata::GroupedCountByteSize,
};

fn default_config(encoding: EncodingConfigWithFraming) -> AzureBlobSinkConfig {
    AzureBlobSinkConfig {
        connection_string: Default::default(),
        authorization: Default::default(),
        storage_account: Default::default(),
        container_name: Default::default(),
        blob_prefix: Default::default(),
        blob_time_format: Default::default(),
        blob_append_uuid: Default::default(),
        encoding,
        compression: Compression::gzip_default(),
        batch: Default::default(),
        request: Default::default(),
        acknowledgements: Default::default(),
        tls_server_certificate: None,
    }
}

#[test]
fn generate_config() {
    crate::test_util::test_generate_config::<AzureBlobSinkConfig>();
}

#[test]
fn azure_blob_build_request_without_compression() {
    let log = Event::Log(LogEvent::from("test message"));
    let compression = Compression::None;
    let container_name = String::from("logs");
    let sink_config = AzureBlobSinkConfig {
        blob_prefix: "blob".try_into().unwrap(),
        container_name: container_name.clone(),
        authorization: Some(AzureBlobSinkAuthorization::ConnectionString{
             connection_string:
            String::from(
                "DefaultEndpointsProtocol=https;AccountName=mylogstorage;AccountKey=storageaccountkeybase64encoded;EndpointSuffix=core.windows.net"
            ).into()
        }        ),
        storage_account: Some(Url::parse("https://mylogstorage.blob.core.windows.net/").unwrap()),
        ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
    };
    let blob_time_format = String::from("");
    let blob_append_uuid = false;

    let key = sink_config
        .key_partitioner()
        .unwrap()
        .partition(&log)
        .expect("key wasn't provided");

    let request_options = AzureBlobRequestOptions {
        container_name,
        blob_time_format,
        blob_append_uuid,
        encoder: (
            Default::default(),
            Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                TextSerializerConfig::default().build().into(),
            ),
        ),
        compression,
    };

    let mut byte_size = GroupedCountByteSize::new_untagged();
    byte_size.add_event(&log, log.estimated_json_encoded_size_of());

    let (metadata, request_metadata_builder, _events) =
        request_options.split_input((key, vec![log]));

    let payload = EncodeResult::uncompressed(Bytes::new(), byte_size);
    let request_metadata = request_metadata_builder.build(&payload);
    let request = request_options.build_request(metadata, request_metadata, payload);

    assert_eq!(request.metadata.partition_key, "blob.log".to_string());
    assert_eq!(request.content_encoding, None);
    assert_eq!(request.content_type, "text/plain");
}

#[test]
fn azure_blob_build_request_with_compression() {
    let log = Event::Log(LogEvent::from("test message"));
    let compression = Compression::gzip_default();
    let container_name = String::from("logs");
    let sink_config = AzureBlobSinkConfig {
        blob_prefix: "blob".try_into().unwrap(),
        container_name: container_name.clone(),
        ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
    };
    let blob_time_format = String::from("");
    let blob_append_uuid = false;

    let key = sink_config
        .key_partitioner()
        .unwrap()
        .partition(&log)
        .expect("key wasn't provided");

    let request_options = AzureBlobRequestOptions {
        container_name,
        blob_time_format,
        blob_append_uuid,
        encoder: (
            Default::default(),
            Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                TextSerializerConfig::default().build().into(),
            ),
        ),
        compression,
    };

    let mut byte_size = GroupedCountByteSize::new_untagged();
    byte_size.add_event(&log, log.estimated_json_encoded_size_of());

    let (metadata, request_metadata_builder, _events) =
        request_options.split_input((key, vec![log]));

    let payload = EncodeResult::uncompressed(Bytes::new(), byte_size);
    let request_metadata = request_metadata_builder.build(&payload);
    let request = request_options.build_request(metadata, request_metadata, payload);

    assert_eq!(request.metadata.partition_key, "blob.log.gz".to_string());
    assert_eq!(request.content_encoding, Some("gzip"));
    assert_eq!(request.content_type, "text/plain");
}

#[test]
fn azure_blob_build_request_with_time_format() {
    let log = Event::Log(LogEvent::from("test message"));
    let compression = Compression::None;
    let container_name = String::from("logs");
    let sink_config = AzureBlobSinkConfig {
        blob_prefix: "blob".try_into().unwrap(),
        container_name: container_name.clone(),
        ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
    };
    let blob_time_format = String::from("%F");
    let blob_append_uuid = false;

    let key = sink_config
        .key_partitioner()
        .unwrap()
        .partition(&log)
        .expect("key wasn't provided");

    let request_options = AzureBlobRequestOptions {
        container_name,
        blob_time_format,
        blob_append_uuid,
        encoder: (
            Default::default(),
            Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                TextSerializerConfig::default().build().into(),
            ),
        ),
        compression,
    };

    let mut byte_size = GroupedCountByteSize::new_untagged();
    byte_size.add_event(&log, log.estimated_json_encoded_size_of());

    let (metadata, request_metadata_builder, _events) =
        request_options.split_input((key, vec![log]));

    let payload = EncodeResult::uncompressed(Bytes::new(), byte_size);
    let request_metadata = request_metadata_builder.build(&payload);
    let request = request_options.build_request(metadata, request_metadata, payload);

    assert_eq!(
        request.metadata.partition_key,
        format!("blob{}.log", Utc::now().format("%F"))
    );
    assert_eq!(request.content_encoding, None);
    assert_eq!(request.content_type, "text/plain");
}

#[test]
fn azure_blob_build_request_with_uuid() {
    let log = Event::Log(LogEvent::from("test message"));
    let compression = Compression::None;
    let container_name = String::from("logs");
    let sink_config = AzureBlobSinkConfig {
        blob_prefix: "blob".try_into().unwrap(),
        container_name: container_name.clone(),
        ..default_config((None::<FramingConfig>, TextSerializerConfig::default()).into())
    };
    let blob_time_format = String::from("");
    let blob_append_uuid = true;

    let key = sink_config
        .key_partitioner()
        .unwrap()
        .partition(&log)
        .expect("key wasn't provided");

    let request_options = AzureBlobRequestOptions {
        container_name,
        blob_time_format,
        blob_append_uuid,
        encoder: (
            Default::default(),
            Encoder::<Framer>::new(
                NewlineDelimitedEncoder::default().into(),
                TextSerializerConfig::default().build().into(),
            ),
        ),
        compression,
    };

    let mut byte_size = GroupedCountByteSize::new_untagged();
    byte_size.add_event(&log, log.estimated_json_encoded_size_of());

    let (metadata, request_metadata_builder, _events) =
        request_options.split_input((key, vec![log]));

    let payload = EncodeResult::uncompressed(Bytes::new(), byte_size);
    let request_metadata = request_metadata_builder.build(&payload);
    let request = request_options.build_request(metadata, request_metadata, payload);

    assert_ne!(request.metadata.partition_key, "blob.log".to_string());
    assert_eq!(request.content_encoding, None);
    assert_eq!(request.content_type, "text/plain");
}

#[tokio::test]
async fn azure_blob_credentials_from_developer_tools_credential() {
    use crate::sinks::azure_common::config::credential_from_authorization;

    let config = toml::from_str::<AzureBlobSinkConfig>(
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"
            [authorization]
            azure_credential_kind="developer_tools_credential"
        "#,
    )
    .expect("Config parsing failed");

    assert_eq!(
        config.storage_account.unwrap().as_str(),
        "https://my-dce-5kyl.eastus-1.storage.azure.com/"
    );
    assert_eq!(
        std::option::Option::Some(AzureBlobSinkAuthorization::DeveloperToolsCredential),
        config.authorization
    );

    let credential = credential_from_authorization(config.authorization.unwrap())
        .expect("Failed to create credential from Developer Tools Credential authorization");
    // Verify that we can successfully obtain a token from the credential, which confirms it's working properly.
    assert!(
        credential
            .get_token(&["https://storage.azure.com/.default"], None)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn azure_blob_credentials_from_connection_string_credential() {
    use crate::sinks::azure_common::config::credential_from_authorization;

    let config = toml::from_str::<AzureBlobSinkConfig>(
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="connection_string"
            connection_string = "DefaultEndpointsProtocol=https;AccountName=my-dce-5kyl;AccountKey=your_account_key;EndpointSuffix=core.windows.net"
        "#,
    );
    let config = match config {
        Err(e) => {
            panic!("Unexpected error message: {e}");
        }
        Ok(config) => config,
    };

    assert_eq!(
        config.storage_account.unwrap().as_str(),
        "https://my-dce-5kyl.eastus-1.storage.azure.com/"
    );
    assert_eq!(
        Some(AzureBlobSinkAuthorization::ConnectionString{
            connection_string: "DefaultEndpointsProtocol=https;AccountName=my-dce-5kyl;AccountKey=your_account_key;EndpointSuffix=core.windows.net".to_string().into()
        }),
        config.authorization
    );

    credential_from_authorization(config.authorization.unwrap())
        .expect_err("Succeeded in creating credential from Connection String authorization");
}

// Verifies successful parsing of all supported credential types in the config, even if the credentials themselves are not valid.
#[tokio::test]
async fn azure_blob_credentials_from_various_identity_credentials() {
    let configs = vec![
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="connection_string"
            connection_string = "DefaultEndpointsProtocol=https;AccountName=my-dce-5kyl;AccountKey=your_account_key;EndpointSuffix=core.windows.net"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="azure_cli_credential"
            tenant_id = "01-23456789-0123-4567-8901-234567890123"
            subscription="01-23456789-0123-4567-8901-234567890123"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"
            connection_string = "DefaultEndpointsProtocol=https;AccountName=my-dce-5kyl;AccountKey=your_account_key;EndpointSuffix=core.windows.net"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="azure_developer_cli_credential"
            tenant_id = "01-23456789-0123-4567-8901-234567890123"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="azure_pipelines_credential"
            tenant_id = "23456789-0123-4567-8901-234567890123"
            subscription_id = "23456789-0123-4567-8901-234567890123"
            service_connection_id = "01-23456789-0123-4567-89012341234"
            system_access_token = "fake_token"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="workload_identity_credential"
            client_id = "23456789-0123-4567-8901-234567890123"
            tenant_id = "23456789-0123-4567-8901-234567890123"
            subscription_id = "23456789-0123-4567-8901-234567890123"
            system_access_token= "fake_token"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="managed_identity_credential"
            managed_identity_id = "01-23456789-0123-4567-8901-234567890123"
            managed_identity_type = "SystemAssigned"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="client_assertion_credential"
            tenant_id = "01-23456789-0123-4567-8901-234567890123"
            client_id = "01-23456789-0123-4567-8901-234567890123"
            subscription_id = "01-23456789-0123-4567-8901-234567890123"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="client_certificate_credential"
            tenant_id = "01-23456789-0123-4567-8901-234567890123"
            client_id = "01-23456789-0123-4567-8901-234567890123"
            certificate = "==== BEGIN CERTIFICATE====\nbase64encodedcertificate\n==== END CERTIFICATE===="
            certificate_password = "fake_password"
        "#,
        r#"
            storage_account = "https://my-dce-5kyl.eastus-1.storage.azure.com"
            container_name = "test-container"
            [encoding]
            codec="json"

            [authorization]
            azure_credential_kind="client_secret_credential"
            tenant_id = "01-23456789-0123-4567-8901-234567890123"
            client_id = "01-23456789-0123-4567-8901-234567890123"
            client_secret = "fake_secret"
        "#,
    ];
    for config_str in configs {
        let config = toml::from_str::<AzureBlobSinkConfig>(config_str);
        if let Err(e) = &config {
            panic!("Unexpected error message for config: {config_str}\nError: {e}");
        }
    }
}
