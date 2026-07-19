use super::basics::*;
use crate::helpers::*;
use crate::*;

/// Limited `did:web` resolver backed by explicitly registered documents.
#[derive(Clone, Debug, Default)]
pub struct DidWebResolver {
    documents: BTreeMap<Did, DidDocument>,
}

/// Host-fetched `did:web` document response validated by the SDK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebDocumentOutcome {
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl DidWebResolver {
    /// Create an empty `did:web` resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a limited `did:web` document.
    pub fn insert(&mut self, document: DidDocument) -> Result<()> {
        if document.id.method() != "web" || did_web_document_url(&document.id).is_none() {
            return Err(Error::Protocol("unsupported did:web form".to_owned()));
        }
        document.validate()?;
        self.documents.insert(document.id.clone(), document);
        Ok(())
    }

    /// Return the HTTPS DID document URL for the limited supported form.
    pub fn document_url(did: &Did) -> Result<String> {
        did_web_document_url(did)
            .ok_or_else(|| Error::Protocol("unsupported did:web form".to_owned()))
    }

    /// Validate a host-fetched HTTPS response and cache the DID document.
    pub fn insert_from_https_response(
        &mut self,
        did: &Did,
        response: DidWebDocumentOutcome,
    ) -> Result<DidDocument> {
        let expected_url = Self::document_url(did)?;
        if response.url != expected_url {
            return Err(Error::Protocol("did:web response URL mismatch".to_owned()));
        }
        if !is_allowed_did_web_content_type(&response.content_type) {
            return Err(Error::Protocol(
                "unsupported did:web content type".to_owned(),
            ));
        }
        if response.body.len() > DID_WEB_MAX_DOCUMENT_BYTES {
            return Err(Error::Protocol(
                "did:web document exceeds size limit".to_owned(),
            ));
        }
        let document: DidDocument = serde_json::from_slice(&response.body)?;
        if &document.id != did {
            return Err(Error::Protocol("did:web document id mismatch".to_owned()));
        }
        self.insert(document.clone())?;
        Ok(document)
    }
}

impl DidResolver for DidWebResolver {
    fn supports(&self, did: &Did) -> bool {
        did.method() == "web" && did_web_document_url(did).is_some()
    }

    fn resolve_did(&self, did: &Did) -> Result<DidDocument> {
        if !self.supports(did) {
            return Err(Error::Protocol(
                "unsupported DID method for did:web resolver".to_owned(),
            ));
        }
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Protocol("did:web document not found".to_owned()))
    }
}
