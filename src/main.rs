use std::process::exit;

use clap::Parser;
use error_stack::{
    Report,
    fmt::{Charset, ColorMode},
};
use rustls::crypto::aws_lc_rs;
use vault_unseal::{cli::Cli, init_cfg, init_log};

#[tokio::main]
async fn main() {
    aws_lc_rs::default_provider().install_default().unwrap();

    let supports_color = supports_color::on_cached(supports_color::Stream::Stdout)
        .is_some_and(|level| level.has_basic);

    let color_mode = if supports_color {
        ColorMode::Color
    } else {
        ColorMode::None
    };

    let supports_unicode = supports_unicode::on(supports_unicode::Stream::Stdout);

    let charset = if supports_unicode {
        Charset::Utf8
    } else {
        Charset::Ascii
    };

    Report::set_color_mode(color_mode);
    Report::set_charset(charset);

    let cli = Cli::parse();
    let cfg = match init_cfg(cli) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e:?}");
            exit(1);
        }
    };

    if let Err(e) = init_log(cfg.clone()) {
        eprintln!("{e:?}");
        exit(1);
    }

    if let Err(e) = vault_unseal::unseal(cfg).await {
        eprintln!("{e:?}");
        exit(1);
    };
}
