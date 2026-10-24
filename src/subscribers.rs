//! Subscriber types.
//!
//! Subscribers listen on certain event bus addresses and receive messages.
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use tokio::sync::{mpsc::UnboundedReceiver, oneshot};

use crate::{EventBus, Message, error::Result};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// A subscriber that receives messages from the event bus.
pub trait Subscriber {
    /// Removes the subscriber from the event bus.
    fn unsubscribe(self, eventbus: &EventBus) -> impl Future<Output = Result<()>> + Send;
}

/// A subscriber with an unbounded message queue.
pub struct UnboundedSubscriber {
    pub(crate) id: u64,
    address: Arc<str>,
    receiver: UnboundedReceiver<Arc<Message>>,
}

/// A subscriber that receives exactly one message. Once the message is
/// received, the subscriber is automatically deregistered from the event bus
/// and cannot be used anymore.
pub struct OnceSubscriber {
    pub(crate) id: u64,
    address: Arc<str>,
    receiver: oneshot::Receiver<Arc<Message>>,
}

impl UnboundedSubscriber {
    pub(crate) fn new(address: Arc<str>, receiver: UnboundedReceiver<Arc<Message>>) -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            address,
            receiver,
        }
    }

    /// Receives the next message.
    ///
    /// This method returns None if the event bus has been shut down and there
    /// are no remaining messages in the subscriber's message queue.
    ///
    /// If there are no messages in the subscribers's message queue, but the
    /// event bus has not yet been shut down, this method will wait for a new
    /// message to receive or for the event bus to be shut down.
    pub async fn recv(&mut self) -> Option<Arc<Message>> {
        self.receiver.recv().await
    }
}

impl Subscriber for UnboundedSubscriber {
    async fn unsubscribe(self, eventbus: &EventBus) -> Result<()> {
        eventbus.unsubscribe(self.id, self.address).await
    }
}

impl OnceSubscriber {
    pub(crate) fn new(address: Arc<str>, receiver: oneshot::Receiver<Arc<Message>>) -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            address,
            receiver,
        }
    }
}

impl Subscriber for OnceSubscriber {
    async fn unsubscribe(self, eventbus: &EventBus) -> Result<()> {
        eventbus.unsubscribe(self.id, self.address).await
    }
}

impl Future for OnceSubscriber {
    type Output = Result<Arc<Message>, oneshot::error::RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.receiver).poll(cx)
    }
}
