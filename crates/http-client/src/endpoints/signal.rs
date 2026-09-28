//! Encrypted-only Signal send and live-subscribe endpoint methods.

use std::time::{Duration, Instant};

use arkret_models_collaboration::signal_operations::SignalSubmitOutcome;
use arkret_wire::{SignalEnvelope, SignalStreamFrame};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Method, Response};

use crate::client_internals::{MAX_RESPONSE_BODY_BYTES, read_body_limited};
use crate::{Client, Error, Result};

/// Metadata from the actual Signal HTTP request. It contains no encrypted
/// envelope, credentials, response body or target-specific header values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalSendTransportObservation {
    pub status: u16,
    pub http_version: String,
    pub content_type: String,
    pub start_to_full_response: Duration,
}

#[cfg(not(target_arch = "wasm32"))]
type BoxSignalSubscribeFrameStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<SignalStreamFrame>> + Send>>;

#[cfg(target_arch = "wasm32")]
type BoxSignalSubscribeFrameStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<SignalStreamFrame>>>>;

/// Validated frame stream for `ak.self.signal.stream.subscribe.v1`.
pub struct SignalSubscribeFrameStream {
    inner: BoxSignalSubscribeFrameStream,
    terminal: bool,
    failed: bool,
}

impl SignalSubscribeFrameStream {
    pub async fn next_frame(&mut self) -> Result<Option<SignalStreamFrame>> {
        use futures_util::StreamExt;

        if self.failed {
            return Err(Error::Protocol(
                "signal subscribe stream was already rejected".to_owned(),
            ));
        }
        if self.terminal {
            return Ok(None);
        }
        let frame = match self.inner.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(error)) => {
                self.failed = true;
                return Err(error);
            }
            None => return Ok(None),
        };
        frame.validate().map_err(|error| {
            self.failed = true;
            Error::Protocol(format!("invalid signal subscribe frame: {error}"))
        })?;
        if matches!(
            frame,
            SignalStreamFrame::Drain { .. } | SignalStreamFrame::Unauthorized { .. }
        ) {
            self.terminal = true;
        }
        Ok(Some(frame))
    }

    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }
}

impl Client {
    /// Send one encrypted Signal envelope.
    pub async fn signal_send(&self, envelope: &SignalEnvelope) -> Result<SignalSubmitOutcome> {
        self.signal_send_with_transport_observation(envelope)
            .await
            .map(|(outcome, _observation)| outcome)
    }

    /// Send through the same production path and return the bounded HTTP
    /// response observation alongside the typed outcome.
    pub async fn signal_send_with_transport_observation(
        &self,
        envelope: &SignalEnvelope,
    ) -> Result<(SignalSubmitOutcome, SignalSendTransportObservation)> {
        envelope.validate_structural()?;
        let request = self.canonical_json_body(
            self.request(Method::POST, "/_arkret/self/signal")?,
            envelope,
        )?;
        let started = Instant::now();
        let response = self.send_response(request).await?;
        let status = response.status().as_u16();
        #[cfg(not(target_arch = "wasm32"))]
        let http_version = format!("{:?}", response.version());
        #[cfg(target_arch = "wasm32")]
        let http_version = String::new();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = read_body_limited(response, MAX_RESPONSE_BODY_BYTES).await?;
        let start_to_full_response = started.elapsed();
        let outcome = serde_json::from_slice(&body)?;
        Ok((
            outcome,
            SignalSendTransportObservation {
                status,
                http_version,
                content_type,
                start_to_full_response,
            },
        ))
    }

    async fn signal_subscribe_stream(&self) -> Result<Response> {
        let request = self.signal_subscribe_request()?;
        let response = self.send_response(request).await?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.contains("application/x-ndjson") {
            return Err(Error::Protocol(
                "signal subscribe requires application/x-ndjson".to_owned(),
            ));
        }
        Ok(response)
    }

    fn signal_subscribe_request(&self) -> Result<reqwest::RequestBuilder> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/x-ndjson"),
        );
        let builder = self
            .request_unbounded(Method::GET, "/_arkret/self/signal/subscribe")?
            .headers(headers);
        crate::client_internals::validate_request_builder(&builder)?;
        Ok(builder)
    }

    /// Open the cursorless, no-catch-up Signal NDJSON receive rail.
    ///
    /// A Signal is momentary — a call invite, a typing indicator — so this is
    /// the rail that suffers most from reading the bounded response only after
    /// it closes. `subscribe_body` reads it incrementally wherever the
    /// transport exposes the body and falls back only when it does not.
    pub async fn signal_subscribe_frames(&self) -> Result<SignalSubscribeFrameStream> {
        use futures_util::StreamExt;

        let response = self.signal_subscribe_stream().await?;
        let inner: BoxSignalSubscribeFrameStream =
            if crate::subscribe_body::streaming_bodies_available() {
                Box::pin(
                    crate::subscribe_body::ndjson_lines(response.bytes_stream()).map(|line| {
                        line.and_then(|line| {
                            serde_json::from_str::<SignalStreamFrame>(&line).map_err(Error::from)
                        })
                    }),
                )
            } else {
                let frames = crate::subscribe_body::bounded_response_lines(response)
                    .await?
                    .into_iter()
                    .map(|line| {
                        serde_json::from_str::<SignalStreamFrame>(&line).map_err(Error::from)
                    })
                    .collect::<Vec<_>>();
                Box::pin(futures_util::stream::iter(frames))
            };
        Ok(SignalSubscribeFrameStream {
            inner,
            terminal: false,
            failed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    fn client() -> Client {
        Client::new(Url::parse("https://alice.example/").unwrap()).unwrap()
    }

    #[test]
    fn signal_subscribe_request_is_cursorless_ndjson() {
        let request = client()
            .signal_subscribe_request()
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.url().path(), "/_arkret/self/signal/subscribe");
        assert!(request.url().query().is_none());
        assert_eq!(
            request.headers().get("accept").unwrap(),
            "application/x-ndjson"
        );
    }

    #[tokio::test]
    async fn terminal_control_frame_stops_local_iteration() {
        let frames = vec![
            Ok(SignalStreamFrame::Heartbeat),
            Ok(SignalStreamFrame::Drain {
                reconnect_after_ms: Some(500),
                reason: Some("rotation".to_owned()),
            }),
            Ok(SignalStreamFrame::Heartbeat),
        ];
        let mut stream = SignalSubscribeFrameStream {
            inner: Box::pin(futures_util::stream::iter(frames)),
            terminal: false,
            failed: false,
        };

        assert_eq!(
            stream.next_frame().await.unwrap(),
            Some(SignalStreamFrame::Heartbeat)
        );
        assert!(matches!(
            stream.next_frame().await.unwrap(),
            Some(SignalStreamFrame::Drain { .. })
        ));
        assert!(stream.is_terminal());
        assert_eq!(stream.next_frame().await.unwrap(), None);
    }
}
