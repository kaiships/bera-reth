//! Minimal payload service that properly handles subscriptions

use reth_payload_builder::{PayloadBuilderHandle, PayloadServiceCommand};
use reth_payload_primitives::{PayloadBuilderAttributes, PayloadTypes};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::{broadcast, mpsc};
use tracing::info;

/// A minimal payload builder service that handles subscriptions properly
pub struct MinimalPayloadService<T: PayloadTypes> {
    /// Receiver for commands
    command_rx: mpsc::UnboundedReceiver<PayloadServiceCommand<T>>,
    /// Event sender for subscriptions
    events_tx: broadcast::Sender<reth_node_api::Events<T>>,
}

impl<T> MinimalPayloadService<T>
where
    T: PayloadTypes,
{
    /// Creates a new minimal payload service with proper event handling
    pub fn new() -> (Self, PayloadBuilderHandle<T>) {
        let (service_tx, command_rx) = mpsc::unbounded_channel();
        let (events_tx, _) = broadcast::channel(100);

        let service = Self { command_rx, events_tx };

        let handle = PayloadBuilderHandle::new(service_tx);
        (service, handle)
    }
}

impl<T> Future for MinimalPayloadService<T>
where
    T: PayloadTypes,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            match this.command_rx.poll_recv(cx) {
                Poll::Ready(Some(cmd)) => match cmd {
                    PayloadServiceCommand::BuildNewPayload(attr, tx) => {
                        info!(target: "sequencer", "Received BuildNewPayload request");
                        let id = attr.payload_id();
                        let _ = tx.send(Ok(id));
                    }
                    PayloadServiceCommand::BestPayload(_, tx) => {
                        info!(target: "sequencer", "Received BestPayload request");
                        let _ = tx.send(None);
                    }
                    PayloadServiceCommand::PayloadTimestamp(_, tx) => {
                        info!(target: "sequencer", "Received PayloadTimestamp request");
                        let _ = tx.send(None);
                    }
                    PayloadServiceCommand::Resolve(_, _, tx) => {
                        info!(target: "sequencer", "Received Resolve request");
                        let _ = tx.send(None);
                    }
                    PayloadServiceCommand::Subscribe(tx) => {
                        info!(target: "sequencer", "Received Subscribe request - sending events receiver");
                        let events_rx = this.events_tx.subscribe();
                        let _ = tx.send(events_rx);
                    }
                },
                Poll::Ready(None) => {
                    info!(target: "sequencer", "Payload service channel closed, shutting down");
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
