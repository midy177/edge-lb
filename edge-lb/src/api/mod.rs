//! HTTP API and UI server. Defaults to 127.0.0.1:18080; listening on a
//! non-loopback address requires auth_token in the config. Only fixed
//! actions (apply/cleanup/failover/verify) are exposed — no arbitrary
//! command execution.

mod auth;
mod handlers;
mod response;
mod router;
mod server;

pub use server::serve;

pub(crate) fn reconcile_automations(cfg: &crate::config::Config) -> anyhow::Result<bool> {
    handlers::automations::reconcile_saved_templates(cfg)
}

pub(crate) fn load_persisted_listeners(
    cfg: &crate::config::Config,
) -> anyhow::Result<Vec<crate::config::Listener>> {
    handlers::listeners::load_for_runtime(cfg)
}
