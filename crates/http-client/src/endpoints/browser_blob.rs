//! Browser multipart consumes a Blob without copying its full body into Rust.
//! Authentication is built by the same Client request path as byte uploads.
use arkret_models_collaboration::objects::blob::{BlobUploadMetadata, BlobUploadResponseBody};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::{Client, Error, Result};

fn js(error: impl Into<JsValue>) -> Error {
    let error = error.into();
    Error::Http(format!("browser Blob upload: {error:?}"))
}

struct AbortUpload {
    window: web_sys::Window,
    controller: web_sys::AbortController,
    timer: i32,
    _callback: Closure<dyn FnMut()>,
}
impl Drop for AbortUpload {
    fn drop(&mut self) {
        self.controller.abort();
        self.window.clear_timeout_with_handle(self.timer);
    }
}

impl Client {
    /// Canonical multipart through Fetch/FormData with a browser-owned Blob.
    /// Future cancellation aborts Fetch; redirects and ambient cookies are refused.
    pub async fn blob_upload_browser_blob(
        &self,
        metadata: &BlobUploadMetadata,
        blob: &web_sys::Blob,
    ) -> Result<BlobUploadResponseBody> {
        if blob.size() as u64 != metadata.size_bytes {
            return Err(Error::Protocol(
                "Blob body size differs from upload metadata".into(),
            ));
        }
        if self.http_message_signer.is_some() {
            return Err(Error::Protocol(
                "streaming browser Blob upload requires the session authentication path".into(),
            ));
        }
        let mime = metadata
            .media_type
            .as_deref()
            .unwrap_or("application/octet-stream");
        if metadata.encryption.is_some()
            && (mime != "application/octet-stream" || metadata.filename.is_some())
        {
            return Err(Error::Protocol(
                "ciphertext upload exposes private metadata".into(),
            ));
        }
        let prepared = self
            .request(reqwest::Method::POST, "/_arkret/self/blob/upload")?
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;
        let headers = web_sys::Headers::new().map_err(js)?;
        for (name, value) in prepared.headers() {
            headers
                .append(
                    name.as_str(),
                    value.to_str().map_err(|e| Error::Protocol(e.to_string()))?,
                )
                .map_err(js)?;
        }
        let form = web_sys::FormData::new().map_err(js)?;
        form.append_with_blob_and_filename(
            "content",
            blob,
            metadata.filename.as_deref().unwrap_or("blob"),
        )
        .map_err(js)?;
        let properties = web_sys::BlobPropertyBag::new();
        properties.set_type("application/json");
        let parts = js_sys::Array::new();
        parts.push(&JsValue::from_str(&serde_json::to_string(
            &metadata.encryption,
        )?));
        let encryption =
            web_sys::Blob::new_with_str_sequence_and_options(&parts, &properties).map_err(js)?;
        form.append_with_blob_and_filename("encryption", &encryption, "encryption")
            .map_err(js)?;
        form.append_with_str("size_bytes", &metadata.size_bytes.to_string())
            .map_err(js)?;
        form.append_with_str("media_type", mime).map_err(js)?;
        if let Some(realm) = &metadata.realm_id {
            form.append_with_str("realm_id", realm.as_str())
                .map_err(js)?;
        }
        if let Some(digest) = &metadata.content_digest {
            form.append_with_str("content_digest", digest.as_str())
                .map_err(js)?;
        }
        if let Some(filename) = &metadata.filename {
            form.append_with_str("filename", filename).map_err(js)?;
        }
        let window = web_sys::window()
            .ok_or_else(|| Error::Http("browser upload requires a Window".into()))?;
        let controller = web_sys::AbortController::new().map_err(js)?;
        let signal = controller.signal();
        let callback = Closure::<dyn FnMut()>::new({
            let controller = controller.clone();
            move || controller.abort()
        });
        // The browser Client has no native reqwest timeout field.
        let timeout = std::time::Duration::from_secs(300);
        let timer = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX),
            )
            .map_err(js)?;
        let _abort = AbortUpload {
            window: window.clone(),
            controller,
            timer,
            _callback: callback,
        };
        let init = web_sys::RequestInit::new();
        init.set_method("POST");
        init.set_headers(&headers);
        init.set_body(&form);
        init.set_credentials(web_sys::RequestCredentials::Omit);
        init.set_redirect(web_sys::RequestRedirect::Error);
        init.set_signal(Some(&signal));
        let request =
            web_sys::Request::new_with_str_and_init(prepared.url().as_str(), &init).map_err(js)?;
        let response: web_sys::Response = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(js)?
            .dyn_into()
            .map_err(js)?;
        let status = response.status();
        let reader: web_sys::ReadableStreamDefaultReader = response
            .body()
            .ok_or_else(|| Error::Protocol("upload outcome is empty".into()))?
            .get_reader()
            .dyn_into()
            .map_err(js)?;
        let mut bytes = Vec::new();
        loop {
            let item = JsFuture::from(reader.read()).await.map_err(js)?;
            if js_sys::Reflect::get(&item, &JsValue::from_str("done"))
                .map_err(js)?
                .as_bool()
                == Some(true)
            {
                break;
            }
            let part = js_sys::Uint8Array::new(
                &js_sys::Reflect::get(&item, &JsValue::from_str("value")).map_err(js)?,
            );
            if bytes.len().saturating_add(part.length() as usize) > 65_536 {
                return Err(Error::Protocol(
                    "upload outcome exceeds the response bound".into(),
                ));
            }
            bytes.extend(part.to_vec());
        }
        if !(200..300).contains(&status) {
            return match serde_json::from_slice::<arkret_wire::Problem>(&bytes) {
                Ok(error) => Err(Error::Api {
                    status,
                    error: Box::new(error),
                }),
                Err(_) => Err(Error::Http(format!("Blob upload returned {status}"))),
            };
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}
