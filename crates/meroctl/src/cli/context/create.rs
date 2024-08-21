use calimero_primitives::context::ContextId;
use camino::Utf8PathBuf;
use clap::Parser;
use libp2p::Multiaddr;
use notify::Watcher;
use reqwest::Client;
use tokio::sync::mpsc;

use crate::cli::RootArgs;
use crate::common::multiaddr_to_url;
use crate::config_file::ConfigFile;

#[derive(Debug, Parser)]
pub struct CreateCommand {
    /// The application ID to attach to the context
    #[clap(long, short = 'a', conflicts_with = "watch")]
    application_id: Option<calimero_primitives::application::ApplicationId>,

    /// Path to the application file to watch and install locally
    #[clap(long, short = 'w')]
    watch: Option<Utf8PathBuf>,
    #[clap(requires = "watch")]
    metadata: Option<Vec<u8>>,

    #[clap(long, short = 'c', requires = "watch")]
    context_id: Option<ContextId>,

    #[clap(long, short = 'p')]
    params: Option<String>,
}

impl CreateCommand {
    pub async fn run(self, root_args: RootArgs) -> eyre::Result<()> {
        let path = root_args.home.join(&root_args.node_name);

        if !ConfigFile::exists(&path) {
            eyre::bail!("Config file does not exist")
        };

        let Ok(config) = ConfigFile::load(&path) else {
            eyre::bail!("Failed to load config file")
        };

        let Some(multiaddr) = config.network.server.listen.first() else {
            eyre::bail!("No address.")
        };

        let client = Client::new();

        match self {
            CreateCommand {
                application_id: Some(app_id),
                watch: None,
                context_id: None,
                metadata: None,
                params,
            } => {
                create_context(&client, multiaddr, app_id, None, params).await?;
            }
            CreateCommand {
                application_id: None,
                watch: Some(path),
                context_id,
                metadata,
                params,
            } => {
                let path = path.canonicalize_utf8()?;
                let application_id =
                    install_app(&client, multiaddr, path.clone(), metadata.clone()).await?;
                let context_id = match context_id {
                    Some(context_id) => {
                        create_context(&client, multiaddr, application_id, Some(context_id), params)
                            .await?
                    }
                    None => {
                        create_context(&client, multiaddr, application_id, None, params).await?
                    }
                };
                watch_app_and_update_context(&client, multiaddr, context_id, path, metadata)
                    .await?;
            }
            _ => eyre::bail!("Invalid command configuration"),
        }

        Ok(())
    }
}

async fn create_context(
    client: &Client,
    base_multiaddr: &Multiaddr,
    application_id: calimero_primitives::application::ApplicationId,
    context_id: Option<ContextId>,
    params: Option<String>,
) -> eyre::Result<calimero_primitives::context::ContextId> {
    if !app_installed(&base_multiaddr, &application_id, client).await? {
        eyre::bail!("Application is not installed on node.")
    }

    let url = multiaddr_to_url(base_multiaddr, "admin-api/dev/contexts")?;
    let request = calimero_server_primitives::admin::CreateContextRequest {
        application_id,
        context_id,
        initialization_params: params.map(String::into_bytes).unwrap_or_default(),
    };

    let response = client.post(url).json(&request).send().await?;

    if response.status().is_success() {
        let context_response: calimero_server_primitives::admin::CreateContextResponse =
            response.json().await?;
        let context = context_response.data.context;

        println!("Context `\x1b[36m{}\x1b[0m` created!", context.id);

        println!(
            "Context{{\x1b[36m{}\x1b[0m}} -> Application{{\x1b[36m{}\x1b[0m}}",
            context.id, context.application_id
        );

        return Ok(context.id);
    }

    let status = response.status();
    let error_text = response.text().await?;

    eyre::bail!(
        "Request failed with status: {}. Error: {}",
        status,
        error_text
    );
}

async fn watch_app_and_update_context(
    client: &Client,
    base_multiaddr: &Multiaddr,
    context_id: calimero_primitives::context::ContextId,
    path: Utf8PathBuf,
    metadata: Option<Vec<u8>>,
) -> eyre::Result<()> {
    let (tx, mut rx) = mpsc::channel(1);

    let handle = tokio::runtime::Handle::current();
    let mut watcher = notify::recommended_watcher(move |evt| {
        handle.block_on(async {
            let _ = tx.send(evt).await;
        })
    })?;

    watcher.watch(path.as_std_path(), notify::RecursiveMode::NonRecursive)?;

    println!("(i) Watching for changes to \"\x1b[36m{}\x1b[0m\"", path);

    while let Some(event) = rx.recv().await {
        let event = match event {
            Ok(event) => event,
            Err(err) => {
                eprintln!("\x1b[1mERROR\x1b[0m: {:?}", err);
                continue;
            }
        };

        match event.kind {
            notify::EventKind::Modify(notify::event::ModifyKind::Data(_)) => {}
            notify::EventKind::Remove(_) => {
                eprintln!("\x1b[33mWARN\x1b[0m: file removed, ignoring..");
                continue;
            }
            _ => continue,
        }

        let application_id =
            install_app(&client, base_multiaddr, path.clone(), metadata.clone()).await?;

        update_context_application(client, base_multiaddr, context_id, application_id).await?;
    }

    Ok(())
}

async fn update_context_application(
    client: &Client,
    base_multiaddr: &Multiaddr,
    context_id: calimero_primitives::context::ContextId,
    application_id: calimero_primitives::application::ApplicationId,
) -> eyre::Result<()> {
    let url = multiaddr_to_url(
        base_multiaddr,
        &format!("admin-api/dev/contexts/{}/application", context_id),
    )?;

    let request =
        calimero_server_primitives::admin::UpdateContextApplicationRequest { application_id };

    let response = client.post(url).json(&request).send().await?;

    if response.status().is_success() {
        println!(
            "Context{{\x1b[36m{}\x1b[0m}} -> Application{{\x1b[36m{}\x1b[0m}}",
            context_id, application_id
        );

        return Ok(());
    }

    let status = response.status();
    let error_text = response.text().await?;

    eyre::bail!(
        "Request failed with status: {}. Error: {}",
        status,
        error_text
    );
}

async fn app_installed(
    base_multiaddr: &Multiaddr,
    application_id: &calimero_primitives::application::ApplicationId,
    client: &Client,
) -> eyre::Result<bool> {
    let url = multiaddr_to_url(
        base_multiaddr,
        &format!("admin-api/dev/application/{}", application_id),
    )?;
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        eyre::bail!("Request failed with status: {}", response.status())
    }

    let api_response: calimero_server_primitives::admin::GetApplicationResponse =
        response.json().await?;

    Ok(api_response.data.application.is_some())
}

async fn install_app(
    client: &Client,
    base_multiaddr: &Multiaddr,
    path: Utf8PathBuf,
    metadata: Option<Vec<u8>>,
) -> eyre::Result<calimero_primitives::application::ApplicationId> {
    let install_url = multiaddr_to_url(base_multiaddr, "admin-api/dev/install-application")?;

    let install_request = calimero_server_primitives::admin::InstallDevApplicationRequest {
        version: None,
        path,
        metadata: metadata.unwrap_or_else(Vec::new),
    };

    let install_response = client
        .post(install_url)
        .json(&install_request)
        .send()
        .await?;

    if !install_response.status().is_success() {
        let status = install_response.status();
        let error_text = install_response.text().await?;
        eyre::bail!(
            "Application installation failed with status: {}. Error: {}",
            status,
            error_text
        )
    }

    let response = install_response
        .json::<calimero_server_primitives::admin::InstallApplicationResponse>()
        .await?;

    println!(
        "Application `\x1b[36m{}\x1b[0m` installed!",
        response.data.application_id
    );

    Ok(response.data.application_id)
}
