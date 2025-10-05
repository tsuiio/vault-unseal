use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::warn;

pub struct Shutdown {
    token: CancellationToken,
}

impl Shutdown {
    pub fn new() -> Self {
        let token = CancellationToken::new();
        let token_clone = token.clone();

        tokio::spawn(async move {
            shutdown_signal().await;

            token_clone.cancel();
        });

        Self { token }
    }

    pub async fn wait_for_shutdown(&self) {
        self.token.cancelled().await;
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            warn!("ctrl-c received");
            warn!("shutting down...");
        },
        _ = terminate => {
            warn!("terminate signal received");
            warn!("shutting down...");
        },
    }
}
