//! Metadata trait definition for user-defined types that can be added to the `SharedState` ad-hoc
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::state::SharedState;
    }
}

/// typedef of the `SharedState`'s `metadata` field
pub type MetadataMap = Arc<RwLock<HashMap<String, Box<dyn Metadata>>>>;

/// an implementor of this trait can be cast to [`Any`] as part of a
/// dynamic dispatch system
pub trait AsAny {
    /// return the implementing type as `Any`
    ///
    /// the normal implementation of this is to return `self`
    fn as_any(&self) -> &dyn Any;
}

/// an implementor of the [`Metadata`] trait will be able to store instances
/// of itself in the `metadata` field of the [`SharedState`] struct
#[cfg_attr(feature = "typetag", typetag::serde(tag = "type"))]
pub trait Metadata: AsAny + Send + Sync + Debug {
    /// delegates to the MetaData-implementing type, allowing for comparison
    /// of two MetaData-implementing types
    ///
    /// it's optional to implement this method, but is there if comparison
    /// between two instances of the same type is needed
    fn is_equal(&self, other: &dyn Any) -> bool;
}
