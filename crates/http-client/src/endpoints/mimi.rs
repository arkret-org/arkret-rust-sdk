//! MIMI interoperability endpoint methods on [`Client`].

use arkret_models_collaboration::mimi_operations::{
    MimiIdentifierQueryOutcome, MimiIdentifierQueryRequestBody, MimiProxyDownloadOutcome,
    MimiProxyDownloadRequestBody, MimiReportAbuseOutcome, MimiReportAbuseRequestBody,
    MimiSubmitMessageOutcome, MimiSubmitMessageRequestBody,
};
use arkret_models_collaboration::objects::interop::ProviderDirectory;
use reqwest::Method;

use crate::{Client, Result};

impl Client {
    pub async fn mimi_identifier_query(
        &self,
        request: &MimiIdentifierQueryRequestBody,
    ) -> Result<MimiIdentifierQueryOutcome> {
        request.validate()?;
        self.post("/_arkret/open/mimi/identifiers/query", request)
            .await
    }

    pub async fn mimi_submit_message(
        &self,
        strand_id: &str,
        request: &MimiSubmitMessageRequestBody,
    ) -> Result<MimiSubmitMessageOutcome> {
        crate::reject_path_segment(strand_id)?;
        self.post(
            &format!("/_arkret/open/mimi/strands/{strand_id}/messages"),
            request,
        )
        .await
    }

    pub async fn mimi_proxy_download(
        &self,
        request: &MimiProxyDownloadRequestBody,
    ) -> Result<MimiProxyDownloadOutcome> {
        self.post("/_arkret/open/mimi/proxy-download", request)
            .await
    }

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
