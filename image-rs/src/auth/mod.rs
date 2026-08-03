// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod auth_config;

use std::collections::HashMap;

use oci_client::{secrets::RegistryAuth, Reference};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type AuthResult<T> = std::result::Result<T, AuthError>;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid registry auth file")]
    InvalidRegistryAuthFile,

    #[error("GCP auth error: {0}")]
    GcpAuth(#[from] gcp_auth::Error),
}

#[derive(Deserialize, Serialize, Default)]
pub struct DockerConfigFile {
    auths: HashMap<String, DockerAuthConfig>,
    // TODO: support credential helpers
}

#[derive(Deserialize, Serialize, Default)]
pub struct DockerAuthConfig {
    auth: String,
}

#[derive(Default)]
pub struct Auth {
    docker_config_file: DockerConfigFile,
}

impl Auth {
    pub fn new(auth_file: &[u8]) -> AuthResult<Self> {
        let docker_config_file: DockerConfigFile =
            serde_json::from_slice(auth_file).map_err(|_| AuthError::InvalidRegistryAuthFile)?;
        Ok(Self { docker_config_file })
    }

    /// Get a credential (RegistryAuth) for the given Reference.
    pub async fn credential_for_reference(
        &self,
        reference: &Reference,
    ) -> AuthResult<RegistryAuth> {

        if reference.registry().ends_with("-docker.pkg.dev") {
            // 1. Get an access token minted as the pod's Workload Identity.
            //    `provider()` auto-detects the GKE metadata server at runtime.
            let provider = gcp_auth::provider().await?;
            let scopes = &["https://www.googleapis.com/auth/cloud-platform"];
            let token = provider.token(scopes).await?;

            // 2. Artifact Registry accepts the token as a Basic-auth password,
            //    with the fixed magic username `oauth2accesstoken`.
            return Ok(RegistryAuth::Basic(
                "oauth2accesstoken".to_string(),
                token.as_str().to_string(),
            ));
        }

        // TODO: support credential helpers
        auth_config::credential_from_auth_config(reference, &self.docker_config_file.auths)
    }
}
