use arkret_models_collaboration::governance::join_policy::{
    JoinApplicationGetOutcome, JoinApplicationListOutcome,
};
use reqwest::Method;

use crate::{Client, Error, Result, reject_path_segment};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JoinApplicationListOptions {
    pub cursor: Option<String>,
    pub limit: Option<u16>,
}

impl JoinApplicationListOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    #[must_use]
    pub fn limit(mut self, limit: u16) -> Self {
        self.limit = Some(limit);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.cursor.as_deref().is_some_and(str::is_empty) {
            return Err(Error::Protocol(
                "join application cursor must not be empty".to_owned(),
            ));
        }
        if self.limit.is_some_and(|limit| !(1..=200).contains(&limit)) {
            return Err(Error::Protocol(
                "join application limit must be in 1..=200".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Client {
    pub async fn join_applications(
        &self,
        realm_id: &str,
        options: &JoinApplicationListOptions,
    ) -> Result<JoinApplicationListOutcome> {
        options.validate()?;
        let path = join_application_collection_path(realm_id)?;
        let mut builder = self.request(Method::GET, &path)?;
        if let Some(cursor) = &options.cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = options.limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn join_application(
        &self,
        realm_id: &str,
        application_ref: &str,
    ) -> Result<JoinApplicationGetOutcome> {
        self.get(&join_application_resource_path(realm_id, application_ref)?)
            .await
    }
}

fn join_application_collection_path(realm_id: &str) -> Result<String> {
    reject_path_segment(realm_id)?;
    Ok(format!("/_arkret/self/realms/{realm_id}/join-applications"))
}

fn join_application_resource_path(realm_id: &str, application_ref: &str) -> Result<String> {
    reject_path_segment(application_ref)?;
    Ok(format!(
        "{}/{}",
        join_application_collection_path(realm_id)?,
        application_ref
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_join_application_paths_are_stable() {
        assert_eq!(
            join_application_resource_path(
                "!realm:example.test",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .unwrap(),
            "/_arkret/self/realms/!realm:example.test/join-applications/sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn list_options_enforce_protocol_limit() {
        assert!(
            JoinApplicationListOptions::new()
                .limit(1)
                .validate()
                .is_ok()
        );
        assert!(
            JoinApplicationListOptions::new()
                .limit(200)
                .validate()
                .is_ok()
        );
        assert!(
            JoinApplicationListOptions::new()
                .limit(0)
                .validate()
                .is_err()
        );
        assert!(
            JoinApplicationListOptions::new()
                .limit(201)
                .validate()
                .is_err()
        );
    }
}
