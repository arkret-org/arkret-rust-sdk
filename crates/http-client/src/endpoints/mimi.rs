//! MIMI interoperability endpoint methods on [`Client`].

use arkret_models_collaboration::mimi_operations::{
    MimiReportAbuseOutcome, MimiReportAbuseRequestBody,
};
use arkret_models_collaboration::objects::interop::ProviderDirectory;
use reqwest::Method;

use crate::{Client, Result};

impl Client {
    pub async fn mimi_provider_directory(
        &self,
        provider_id: Option<&str>,
        features: &[String],
    ) -> Result<ProviderDirectory> {
        let mut builder = self.request(Method::GET, "/_arkret/open/mimi/provider-directory")?;
        if let Some(provider_id) = provider_id {
            builder = builder.query(&[("provider_id", provider_id)]);
        }
        for feature in features {
            builder = builder.query(&[("features", feature)]);
        }
        self.send_json(builder).await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: &MimiReportAbuseRequestBody,
    ) -> Result<MimiReportAbuseOutcome> {
        self.post("/_arkret/open/mimi/report-abuse", request).await
    }
}
