mod publisher;
mod subscriber;

pub use self::publisher::{EventPublisher, Publisher};

use tracing::Level;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Event {
    Log { level: Level, message: String },
    Message(String),
    Decision,
    Mutation,
    Action,
    ResponseReceived,
    RequestSent,
    CorpusModified,
}
