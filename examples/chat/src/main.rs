use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Context, Result};
use clap::Parser;
use dispost::distruct::{
    Cluster, ClusterConfigBuilder,
    rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use dispost::{EventBus, EventBusConfigBuilder};
use log::info;
use rustyline_async::{Readline, ReadlineEvent};
use tokio::{select, sync::oneshot};
use tracing_subscriber::EnvFilter;

const ADDRESS: &str = "dispost-example-chat";
const DEFAULT_PORT: u16 = 35000;
const DEFAULT_EVENTBUS_PORT: u16 = 36000;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    bind_addr: IpAddr,

    #[arg(long, default_value_t = DEFAULT_PORT)]
    bind_port: u16,

    #[arg(long)]
    public_addr: String,

    #[arg(long)]
    public_port: u16,

    #[arg(long, default_value_t = DEFAULT_EVENTBUS_PORT)]
    eventbus_bind_port: u16,

    #[arg(long)]
    eventbus_public_port: u16,

    #[arg(long)]
    seed_addr: Option<String>,

    #[arg(long)]
    seed_port: Option<u16>,
}

async fn resolve(addr: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((addr, port))
        .await
        .with_context(|| format!("failed to resolve seed address: {addr}:{port}"))?
        .next()
        .with_context(|| format!("no addresses found for seed: {addr}:{port}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // resolve public addr
    let public_addr = resolve(&cli.public_addr, cli.public_port).await?;
    let eventbus_public_addr = resolve(&cli.public_addr, cli.eventbus_public_port).await?;

    let mut cluster_config_builder = ClusterConfigBuilder::default()
        .with_bind_addr((cli.bind_addr, cli.bind_port).into())
        .with_public_addr(public_addr, cli.public_addr.clone());
    let eventbus_config_builder = EventBusConfigBuilder::default()
        .with_bind_addr((cli.bind_addr, cli.eventbus_bind_port).into())
        .with_public_addr(eventbus_public_addr, cli.public_addr);

    // add seed if there is any
    if let Some(seed_addr) = cli.seed_addr {
        let seed_port = cli.seed_port.unwrap_or(DEFAULT_PORT);
        let resolved_seed_addr = resolve(&seed_addr, seed_port).await?;
        cluster_config_builder = cluster_config_builder.with_seed(resolved_seed_addr, seed_addr);
    }

    // load server certificate and private key
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter("cert.pem")
        .context("failed to read certificate chain file")?
        .collect::<core::result::Result<_, _>>()
        .context("invalid PEM-encoded certificate")?;
    let key = PrivateKeyDer::from_pem_file("key.pem").context("failed to read private key file")?;

    let cluster_config = cluster_config_builder.build(certs.clone(), key.clone_key());
    let eventbus_config = eventbus_config_builder.build(certs, key);

    let cluster = Cluster::spawn(cluster_config).await?;
    let eventbus = EventBus::new(&cluster, eventbus_config)?;

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    let mut subscriber = eventbus.subscribe(ADDRESS).await?;
    info!("Subscribed to '{ADDRESS}'");

    let (mut rl, mut stdout) = Readline::new("> ".to_owned())?;

    loop {
        select! {
            _ = &mut shutdown_rx => {
                break;
            },

            msg = subscriber.recv() => {
                let Some(msg) = msg else {
                    break;
                };
                let msg = std::str::from_utf8(&msg.body).unwrap();
                writeln!(stdout, "Received message: {msg}")?;
            }

            readline_event = rl.readline() => {
                match readline_event {
                    Ok(ReadlineEvent::Line(line)) => {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }

                        rl.add_history_entry(line.to_string());

                        eventbus.publish(ADDRESS, line.as_bytes()).await?;
                    }

                    Ok(ReadlineEvent::Eof) | Ok(ReadlineEvent::Interrupted) => {
                        shutdown_tx.send(()).unwrap();
                        break;
                    }

                    Err(e) => {
                        writeln!(stdout, "input error: {e}")?;
                        break;
                    }
                }
            }
        }
    }

    eventbus.shutdown().await?;
    cluster.shutdown().await?;

    Ok(())
}
