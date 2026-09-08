//! NDJSON framing for the bounded subscribe responses, and the browser
//! capability probe that decides how the body is read.
//!
//! `service-http-binding.md` §3.4 / §5.2 make every subscribe response a
//! *bounded* NDJSON response: the server holds it open for a window, then
//! closes it with a terminal control frame and the client reconnects. Reading
//! that response incrementally and reading it after close are therefore both
//! conformant — they differ only in how late a frame reaches the application.
//!
//! Native transports always read incrementally. On `wasm32` incremental reads
//! need `Response.body`, which a browser (or an intermediary that buffers the
//! whole response) may not expose; reqwest then hands back an *empty* stream
//! rather than an error, which would silently look like a connection that
//! delivered nothing. [`streaming_bodies_available`] turns that into an
//! explicit, latched decision: after two consecutive unusable streamed
//! responses (a zero-byte close or a body read failure before any byte) the
//! process switches to reading the bounded response after close, which is
//! slower but always works. The fallback direction is the safe one — a false
//! positive costs latency, never correctness.

#[cfg(any(target_arch = "wasm32", test))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use futures_util::{Stream, StreamExt};

use crate::{Error, MAX_SUBSCRIBE_FRAME_BYTES, Result};

/// Consecutive zero-byte streamed responses that latch the buffered fallback.
/// One is not enough: a server can legitimately close a window having written
/// nothing if the connection is torn down at exactly the wrong moment.
#[cfg(any(target_arch = "wasm32", test))]
const EMPTY_STREAMED_RESPONSES_BEFORE_FALLBACK: usize = 2;

/// Latching decision on whether the transport hands back response bytes while
/// the response is still open.
///
/// Kept as a plain struct rather than a pile of `cfg`-gated statics so the
/// latch rule itself stays testable on the target the test suite runs on; a
/// native build has nothing to probe and never instantiates it.
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Debug)]
struct StreamingBodyProbe {
    latched: AtomicBool,
    consecutive_empty: AtomicUsize,
}

#[cfg(any(target_arch = "wasm32", test))]
impl StreamingBodyProbe {
    const fn new() -> Self {
        Self {
            latched: AtomicBool::new(false),
            consecutive_empty: AtomicUsize::new(0),
        }
    }

    fn available(&self) -> bool {
        !self.latched.load(Ordering::Relaxed)
    }

    fn observe(&self, total_bytes: usize) {
        if total_bytes > 0 {
            self.consecutive_empty.store(0, Ordering::Relaxed);
            return;
        }
        let empty = self.consecutive_empty.fetch_add(1, Ordering::Relaxed) + 1;
        if empty >= EMPTY_STREAMED_RESPONSES_BEFORE_FALLBACK {
            self.latched.store(true, Ordering::Relaxed);
        }
    }

    fn observe_failure(&self, total_bytes: usize) {
        // A failure after at least one byte proves that streaming is available;
        // it is a transport interruption, not the browser capability failure
        // this latch diagnoses. A pre-byte decode/read failure is operationally
        // identical to the empty stream reqwest returns on other browsers.
        self.observe(total_bytes);
    }
}

#[cfg(target_arch = "wasm32")]
static STREAMING_BODY_PROBE: StreamingBodyProbe = StreamingBodyProbe::new();

/// Whether this process may still read subscribe responses incrementally.
///
/// Always true off `wasm32`: a native transport exposes the body by
/// construction, so there is nothing to probe and nothing to fall back to.
pub(crate) fn streaming_bodies_available() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        STREAMING_BODY_PROBE.available()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}

/// Record how many body bytes one streamed subscribe response produced.
fn observe_streamed_response(total_bytes: usize) {
    #[cfg(target_arch = "wasm32")]
    {
        STREAMING_BODY_PROBE.observe(total_bytes);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = total_bytes;
    }
}

fn observe_streamed_response_failure(total_bytes: usize) {
    #[cfg(target_arch = "wasm32")]
    {
        STREAMING_BODY_PROBE.observe_failure(total_bytes);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = total_bytes;
    }
}

struct LineState<S> {
    chunks: S,
    buffer: Vec<u8>,
    total_bytes: usize,
    finished: bool,
}

/// Split a response byte stream into NDJSON lines.
///
/// One implementation for both targets so the per-line byte ceiling, the
/// trailing-line rule and the blank-line rule cannot drift between them. Blank
/// lines are dropped here rather than by each caller; a line over
/// [`MAX_SUBSCRIBE_FRAME_BYTES`] ends the stream with an error instead of
/// growing an unbounded buffer while waiting for a newline.
pub(crate) fn ndjson_lines<S, B>(chunks: S) -> impl Stream<Item = Result<String>>
where
    S: Stream<Item = reqwest::Result<B>> + Unpin,
    B: AsRef<[u8]>,
{
    futures_util::stream::unfold(
        LineState {
            chunks,
            buffer: Vec::new(),
            total_bytes: 0,
            finished: false,
        },
        |mut state| async move {
            if state.finished {
                return None;
            }
            loop {
                if let Some(index) = state.buffer.iter().position(|byte| *byte == b'\n') {
                    let mut line = state.buffer.drain(..=index).collect::<Vec<u8>>();
                    line.pop();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    match decode_line(line) {
                        Ok(Some(line)) => return Some((Ok(line), state)),
                        Ok(None) => continue,
                        Err(error) => {
                            state.finished = true;
                            return Some((Err(error), state));
                        }
                    }
                }
                if state.buffer.len() > MAX_SUBSCRIBE_FRAME_BYTES {
                    state.finished = true;
                    return Some((
                        Err(Error::Protocol(format!(
                            "subscribe frame exceeds {MAX_SUBSCRIBE_FRAME_BYTES} bytes"
                        ))),
                        state,
                    ));
                }
                match state.chunks.next().await {
                    Some(Ok(chunk)) => {
                        state.total_bytes += chunk.as_ref().len();
                        state.buffer.extend_from_slice(chunk.as_ref());
                    }
                    Some(Err(error)) => {
                        observe_streamed_response_failure(state.total_bytes);
                        state.finished = true;
                        return Some((Err(crate::client_internals::transport_error(error)), state));
                    }
                    None => {
                        observe_streamed_response(state.total_bytes);
                        state.finished = true;
                        // A response that closes without a final newline still
                        // carries a complete frame; the server bounds the
                        // window, not the framing.
                        let trailing = std::mem::take(&mut state.buffer);
                        return match decode_line(trailing) {
                            Ok(Some(line)) => Some((Ok(line), state)),
                            Ok(None) => None,
                            Err(error) => Some((Err(error), state)),
                        };
                    }
                }
            }
        },
    )
}

/// Read a bounded subscribe response after close and split it into NDJSON
/// lines. Used when the transport does not expose the body incrementally.
pub(crate) async fn bounded_response_lines(response: reqwest::Response) -> Result<Vec<String>> {
    let bytes = response
        .bytes()
        .await
        .map_err(crate::client_internals::transport_error)?;
    if bytes.len() > crate::client_internals::MAX_RESPONSE_BODY_BYTES {
        return Err(Error::Protocol(
            "buffered subscribe response exceeds limit".to_owned(),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| Error::Protocol(format!("subscribe response is not UTF-8: {error}")))?;
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.len() > MAX_SUBSCRIBE_FRAME_BYTES {
            return Err(Error::Protocol(format!(
                "subscribe frame exceeds {MAX_SUBSCRIBE_FRAME_BYTES} bytes"
            )));
        }
        if line.trim().is_empty() {
            continue;
        }
        lines.push(line.to_owned());
    }
    Ok(lines)
}

fn decode_line(line: Vec<u8>) -> Result<Option<String>> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|error| Error::Protocol(format!("subscribe frame is not UTF-8: {error}")))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interrupted_body_preserves_completed_lines_and_returns_transport_error() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            connection.read(&mut request).unwrap();
            connection.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{\"kind\":\"frontier\"}\n{\"kind\":",
            ).unwrap();
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
            .get(format!("http://{address}/subscribe"))
            .send()
            .await
            .unwrap();
        let lines = ndjson_lines(response.bytes_stream())
            .collect::<Vec<_>>()
            .await;
        server.join().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].as_deref().unwrap(), "{\"kind\":\"frontier\"}");
        assert!(matches!(&lines[1], Err(Error::Http(_))), "{lines:?}");
    }

    #[test]
    fn malformed_frame_remains_a_protocol_error() {
        let lines = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                ndjson_lines(futures_util::stream::iter([Ok(vec![0xff, b'\n'])]))
                    .collect::<Vec<_>>()
                    .await
            });
        assert!(matches!(&lines[0], Err(Error::Protocol(_))));
    }

    fn lines_of(chunks: Vec<&'static str>) -> Vec<Result<String>> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(async {
                ndjson_lines(futures_util::stream::iter(
                    chunks.into_iter().map(|chunk| Ok(chunk.as_bytes())),
                ))
                .collect::<Vec<_>>()
                .await
            })
    }

    #[test]
    fn a_frame_split_across_chunks_is_reassembled() {
        let lines = lines_of(vec!["{\"kind\":\"heart", "beat\"}\n{\"kind\":\"drain\"}\n"]);
        let lines = lines
            .into_iter()
            .map(std::result::Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            vec!["{\"kind\":\"heartbeat\"}", "{\"kind\":\"drain\"}"]
        );
    }

    #[test]
    fn blank_lines_and_crlf_are_normalized_away() {
        let lines = lines_of(vec!["{\"a\":1}\r\n", "\n", "   \n", "{\"b\":2}"]);
        let lines = lines
            .into_iter()
            .map(std::result::Result::unwrap)
            .collect::<Vec<_>>();
        assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}"]);
    }

    #[test]
    fn a_body_with_no_trailing_newline_still_yields_its_last_frame() {
        let lines = lines_of(vec!["{\"kind\":\"frontier\"}"]);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].as_deref().unwrap(), "{\"kind\":\"frontier\"}");
    }

    #[test]
    fn an_empty_body_yields_nothing() {
        assert!(lines_of(vec![]).is_empty());
        assert!(lines_of(vec!["\n"]).is_empty());
    }

    #[test]
    fn one_empty_streamed_response_does_not_latch_the_fallback() {
        let probe = StreamingBodyProbe::new();
        probe.observe(0);
        assert!(probe.available());
        // A response that did produce bytes proves the transport streams, so
        // the earlier empty one must not accumulate toward the latch.
        probe.observe(64);
        probe.observe(0);
        assert!(probe.available());
    }

    #[test]
    fn consecutive_empty_streamed_responses_latch_the_fallback_permanently() {
        let probe = StreamingBodyProbe::new();
        for _ in 0..EMPTY_STREAMED_RESPONSES_BEFORE_FALLBACK {
            probe.observe(0);
        }
        assert!(!probe.available());
        // Latched means latched: the browser does not grow the capability
        // back mid-session, and re-probing would re-introduce the silent
        // zero-frame connections the latch exists to stop.
        probe.observe(4096);
        assert!(!probe.available());
    }

    #[test]
    fn consecutive_pre_byte_read_failures_latch_the_buffered_fallback() {
        let probe = StreamingBodyProbe::new();
        probe.observe_failure(0);
        assert!(probe.available());
        probe.observe_failure(0);
        assert!(!probe.available());
    }

    #[test]
    fn a_read_failure_after_bytes_does_not_poison_streaming_capability() {
        let probe = StreamingBodyProbe::new();
        probe.observe_failure(0);
        probe.observe_failure(128);
        probe.observe_failure(0);
        assert!(probe.available());
    }
}
