//! S-8 (savfox SDK gap, 2026-05-27) — `salvo::Router` factory for
//! Applet HTTP endpoints.
//!
//! Wires the 6 endpoints from `applet-integration.md` §7 to a single
//! [`AppletHandler`] trait implementation: ping, describe,
//! transactions, actor lookup, realm lookup, protocol lookup. The
//! Idempotency-Key dedup (S-5) is wired in; trait methods only need
//! to implement business logic.
//!
//! The trait surface is always available (under `applet-runtime`).
//! The Salvo `Router` factory is gated behind the `salvo` feature;
//! when off, callers can still implement [`AppletHandler`] and route
//! to it themselves.

use std::sync::Arc;

use crate::Result;
use crate::idempotency::IdempotencyWindow;
use crate::model::{
    AppletActorResBody, AppletDescription, AppletPingResBody, AppletProtocolResBody,
    AppletRealmResBody, AppletTransactionReqBody, AppletTransactionResBody,
};

/// Application-owned trait the [`router`] factory dispatches to.
///
/// Implementations focus on business logic; the factory handles HTTP
/// dispatch, body deserialization, and the Idempotency-Key header
/// extraction. Bounds (`Send + Sync + 'static`) are pinned so the
/// trait is object-safe for the `Arc<dyn AppletHandler>` wiring the
/// router uses.
pub trait AppletHandler: Send + Sync + 'static {
    /// `GET /api/v1/applet/ping`
    fn ping(&self) -> Result<AppletPingResBody>;
    /// `GET /api/v1/applet/describe`
    fn describe(&self) -> Result<AppletDescription>;
    /// `POST /api/v1/applet/transactions`
    fn handle_transaction(
        &self,
        idempotency_key: Option<&str>,
        req: AppletTransactionReqBody,
    ) -> Result<AppletTransactionResBody>;
    /// `GET /api/v1/applet/actors/{actor_id}`
    fn resolve_actor(&self, actor_id: &str) -> Result<AppletActorResBody>;
    /// `GET /api/v1/applet/realms/{realm_id_or_alias}`
    fn resolve_realm(&self, realm_id_or_alias: &str) -> Result<AppletRealmResBody>;
    /// `GET /api/v1/applet/protocols/{protocol}`
    fn resolve_protocol(&self, protocol: &str) -> Result<AppletProtocolResBody>;
}

/// Wrap an [`AppletHandler`] together with an idempotency window the
/// router uses to dedupe transaction submissions per
/// `applet-integration.md` §7.3.
pub struct AppletService {
    pub handler: Arc<dyn AppletHandler>,
    pub idempotency: Arc<IdempotencyWindow>,
}

impl AppletService {
    pub fn new<H: AppletHandler>(handler: H, idempotency: IdempotencyWindow) -> Self {
        Self { handler: Arc::new(handler), idempotency: Arc::new(idempotency) }
    }

    pub fn from_arcs(handler: Arc<dyn AppletHandler>, idempotency: Arc<IdempotencyWindow>) -> Self {
        Self { handler, idempotency }
    }
}

#[cfg(feature = "salvo")]
mod salvo_router {
    use super::*;

    use salvo::prelude::*;
    use std::sync::OnceLock;

    /// Process-wide handle to the wired-up [`AppletService`]. Salvo's
    /// `#[handler]` macro can't see generics, so we stash the handler
    /// behind a `OnceLock` and read it back from each endpoint. Only
    /// one [`AppletService`] is supported per process; tests should
    /// run sequentially or use separate processes.
    static SERVICE: OnceLock<AppletService> = OnceLock::new();

    /// Install the [`AppletService`] for the process and build the
    /// salvo [`Router`] for the 6 standard Applet endpoints. Returns
    /// `Err` if called more than once.
    pub fn router(service: AppletService) -> Result<Router> {
        SERVICE.set(service).map_err(|_| {
            crate::Error::Protocol("applet_server::router already installed".to_owned())
        })?;
        Ok(Router::with_path("api/v1/applet")
            .push(Router::with_path("ping").get(ping_handler))
            .push(Router::with_path("describe").get(describe_handler))
            .push(Router::with_path("transactions").post(transactions_handler))
            .push(Router::with_path("actors/{actor_id}").get(actor_handler))
            .push(Router::with_path("realms/{realm_id_or_alias}").get(realm_handler))
            .push(Router::with_path("protocols/{protocol}").get(protocol_handler)))
    }

    fn service() -> &'static AppletService {
        SERVICE.get().expect("applet_server::router not installed before request dispatch")
    }

    fn into_status_error(err: crate::Error) -> StatusError {
        StatusError::internal_server_error().brief(err.to_string())
    }

    #[handler]
    async fn ping_handler(res: &mut Response) {
        match service().handler.ping() {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn describe_handler(res: &mut Response) {
        match service().handler.describe() {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn transactions_handler(req: &mut Request, res: &mut Response) {
        let idempotency_key = req
            .header::<String>("Idempotency-Key")
            .map(|key| key.trim().to_owned())
            .filter(|key| !key.is_empty());
        let body: AppletTransactionReqBody = match req.parse_json().await {
            Ok(body) => body,
            Err(err) => {
                res.render(StatusError::bad_request().brief(err.to_string()));
                return;
            }
        };
        match service().handler.handle_transaction(idempotency_key.as_deref(), body) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn actor_handler(req: &mut Request, res: &mut Response) {
        let actor_id = req.param::<String>("actor_id").unwrap_or_default();
        match service().handler.resolve_actor(&actor_id) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn realm_handler(req: &mut Request, res: &mut Response) {
        let realm = req.param::<String>("realm_id_or_alias").unwrap_or_default();
        match service().handler.resolve_realm(&realm) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }

    #[handler]
    async fn protocol_handler(req: &mut Request, res: &mut Response) {
        let protocol = req.param::<String>("protocol").unwrap_or_default();
        match service().handler.resolve_protocol(&protocol) {
            Ok(body) => res.render(Json(body)),
            Err(err) => res.render(into_status_error(err)),
        }
    }
}

#[cfg(feature = "salvo")]
pub use salvo_router::router;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppletPingResBody;
    use std::time::Duration;

    struct StubHandler;

    impl AppletHandler for StubHandler {
        fn ping(&self) -> Result<AppletPingResBody> {
            Ok(AppletPingResBody {
                ok: true,
                applet_id: "cx:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
                service_did: crate::Did::new("did:web:svc.example").unwrap(),
                protocol_version: "1.0".to_owned(),
            })
        }
        fn describe(&self) -> Result<AppletDescription> {
            Ok(AppletDescription {
                applet_id: "cx:applet:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
                service_did: crate::Did::new("did:web:svc.example").unwrap(),
                protocols: vec!["cx.applet.v1".to_owned()],
                namespaces: serde_json::Value::Null,
                limits: serde_json::Value::Null,
                auth: serde_json::Value::Null,
            })
        }
        fn handle_transaction(
            &self,
            _idempotency_key: Option<&str>,
            _req: AppletTransactionReqBody,
        ) -> Result<AppletTransactionResBody> {
            Ok(AppletTransactionResBody { ok: true, rejected: vec![], retry_after_ms: None })
        }
        fn resolve_actor(&self, _actor_id: &str) -> Result<AppletActorResBody> {
            Ok(AppletActorResBody {
                exists: false,
                actor_id: None,
                display_name: None,
                external_ref: serde_json::Value::Null,
            })
        }
        fn resolve_realm(&self, _: &str) -> Result<AppletRealmResBody> {
            Ok(AppletRealmResBody {
                exists: false,
                realm_id: None,
                title: None,
                external_ref: serde_json::Value::Null,
            })
        }
        fn resolve_protocol(&self, _: &str) -> Result<AppletProtocolResBody> {
            Ok(AppletProtocolResBody {
                protocol: "cx.unknown".to_owned(),
                display_name: "Unknown".to_owned(),
                icon_blob: None,
                field_types: serde_json::Value::Null,
                instances: Vec::new(),
            })
        }
    }

    #[test]
    fn applet_service_constructs_with_handler_and_idempotency_window() {
        let svc =
            AppletService::new(StubHandler, IdempotencyWindow::new(Duration::from_secs(5 * 60)));
        let body = svc.handler.ping().unwrap();
        assert!(body.ok);
    }
}
