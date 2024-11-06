use std::time::Duration;

use calimero_network::stream::{Message, Stream};
use calimero_primitives::context::ContextId;
use eyre::{bail, Result as EyreResult};
use futures_util::{SinkExt, StreamExt};
use libp2p::gossipsub::TopicHash;
use libp2p::PeerId;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::thread_rng;
use tokio::time::timeout;
use tracing::{debug, error};

use crate::types::{InitPayload, StreamMessage};
use crate::Node;

mod blobs;
mod state;

#[derive(Copy, Clone, Debug)]
pub struct SyncConfig {
    pub timeout: Duration,
    pub interval: Duration,
}

async fn send(stream: &mut Stream, message: &StreamMessage<'_>) -> EyreResult<()> {
    let message = borsh::to_vec(message)?;

    stream.send(Message::new(message)).await?;

    Ok(())
}

async fn recv(
    stream: &mut Stream,
    duration: Duration,
) -> EyreResult<Option<StreamMessage<'static>>> {
    let Some(message) = timeout(duration, stream.next()).await? else {
        return Ok(None);
    };

    let message = borsh::from_slice(&message?.data)?;

    Ok(Some(message))
}

#[derive(Default)]
struct Sequencer {
    current: usize,
}

impl Sequencer {
    fn current(&self) -> usize {
        self.current
    }

    fn test(&mut self, idx: usize) -> eyre::Result<()> {
        if self.current != idx {
            bail!(
                "out of sequence message: expected {}, got {}",
                self.current,
                idx
            );
        }

        self.current += 1;

        Ok(())
    }

    fn next(&mut self) -> usize {
        let current = self.current;
        self.current += 1;
        current
    }
}

impl Node {
    pub(crate) async fn initiate_sync(
        &self,
        context_id: ContextId,
        chosen_peer: PeerId,
    ) -> EyreResult<()> {
        let mut context = self.ctx_manager.sync_context_config(context_id).await?;

        let Some(application) = self.ctx_manager.get_application(&context.application_id)? else {
            bail!("application not found: {}", context.application_id);
        };

        let identities = self.ctx_manager.get_context_owned_identities(context.id)?;

        let Some(our_identity) = identities.into_iter().choose(&mut thread_rng()) else {
            bail!("no identities found for context: {}", context.id);
        };

        let mut stream = self.network_client.open_stream(chosen_peer).await?;

        if !self.ctx_manager.has_blob_available(application.blob)? {
            self.initiate_blob_share_process(
                &context,
                our_identity,
                application.blob,
                application.size,
                &mut stream,
            )
            .await?;
        }

        self.initiate_state_sync_process(&mut context, our_identity, &mut stream)
            .await
    }

    pub(crate) async fn handle_opened_stream(&self, mut stream: Box<Stream>) {
        loop {
            match self.internal_handle_opened_stream(&mut stream).await {
                Ok(None) => break,
                Ok(Some(())) => {}
                Err(err) => {
                    error!(%err, "Failed to handle stream message");

                    if let Err(err) = send(&mut stream, &StreamMessage::OpaqueError).await {
                        error!(%err, "Failed to send error message");
                    }
                }
            }
        }
    }

    async fn internal_handle_opened_stream(&self, stream: &mut Stream) -> EyreResult<Option<()>> {
        let Some(message) = recv(stream, self.sync_config.timeout).await? else {
            return Ok(None);
        };

        let (context_id, their_identity, payload) = match message {
            StreamMessage::Init {
                context_id,
                party_id,
                payload,
            } => (context_id, party_id, payload),
            unexpected @ (StreamMessage::Message { .. } | StreamMessage::OpaqueError) => {
                bail!("expected initialization handshake, got {:?}", unexpected)
            }
        };

        let Some(mut context) = self.ctx_manager.get_context(&context_id)? else {
            bail!("context not found: {}", context_id);
        };

        let mut updated = None;

        if !self
            .ctx_manager
            .has_context_identity(context_id, their_identity)?
        {
            updated = Some(self.ctx_manager.sync_context_config(context_id).await?);

            if !self
                .ctx_manager
                .has_context_identity(context_id, their_identity)?
            {
                bail!(
                    "unknown context member {} in context {}",
                    their_identity,
                    context_id
                );
            }
        }

        match payload {
            InitPayload::BlobShare { blob_id } => {
                self.handle_blob_share_request(context, their_identity, blob_id, stream)
                    .await?
            }
            InitPayload::StateSync {
                root_hash,
                application_id,
            } => {
                if updated.is_none() && context.application_id != application_id {
                    updated = Some(self.ctx_manager.sync_context_config(context_id).await?);
                }

                if let Some(updated) = updated {
                    if application_id != updated.application_id {
                        bail!(
                            "application mismatch: expected {}, got {}",
                            updated.application_id,
                            application_id
                        );
                    }

                    context = updated;
                }

                self.handle_state_sync_request(
                    context,
                    their_identity,
                    root_hash,
                    application_id,
                    stream,
                )
                .await?
            }
        };

        Ok(Some(()))
    }

    pub async fn perform_interval_sync(&self) {
        let task = async {
            for context_id in self.ctx_manager.get_n_pending_sync_context(3).await {
                if self
                    .internal_perform_interval_sync(context_id)
                    .await
                    .is_some()
                {
                    break;
                }

                debug!(%context_id, "Unable to perform interval sync for context, trying another..");
            }
        };

        if timeout(self.sync_config.interval, task).await.is_err() {
            error!("Timeout while performing interval sync");
        }
    }

    async fn internal_perform_interval_sync(&self, context_id: ContextId) -> Option<()> {
        let peers = self
            .network_client
            .mesh_peers(TopicHash::from_raw(context_id))
            .await;

        for peer_id in peers.choose_multiple(&mut thread_rng(), 3) {
            debug!(%context_id, %peer_id, "Attempting to perform interval triggered sync");

            if let Err(err) = self.initiate_sync(context_id, *peer_id).await {
                error!(%err, "Failed to perform interval sync, trying another peer");
                continue;
            }

            let _ = self
                .ctx_manager
                .clear_context_pending_sync(&context_id)
                .await;

            debug!(%context_id, %peer_id, "Interval triggered sync successfully finished");

            return Some(());
        }

        None
    }
}
