#![macro_use]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::perf,
    rustdoc::broken_intra_doc_links,
    missing_docs,
    clippy::missing_const_for_fn
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::multiple_crate_versions)] // appears to be a false positive; cargo tree doesn't show what clippy yells about

pub mod actions;
pub mod client;
pub mod corpora;
pub mod deciders;
pub mod error;
pub mod fuzzers;
pub mod input;
pub mod mutators;
pub mod observers;
pub mod prelude;
pub mod processors;
pub mod requests;
pub mod responses;
pub mod schedulers;
pub mod state;
pub mod statistics;
mod std_ext;

// re-exported traits, to be available as top-level imports for users
pub use std_ext::convert::{AsBytes, AsInner, IntoInner};
pub use std_ext::ops::Len;
pub use std_ext::tuple::{MatchName, Named};

pub use tuple_list::tuple_list as build_observers;
pub use tuple_list::tuple_list as build_deciders;
pub use tuple_list::tuple_list as build_mutators;
pub use tuple_list::tuple_list as build_processors;
pub use tuple_list::TupleList as DecidersList;
pub use tuple_list::TupleList as ObserversList;
pub use tuple_list::TupleList as MutatorsList;
pub use tuple_list::TupleList as ProcessorsList;

/// Wrapper `Atomic*.fetch_add` to save me from writing `Ordering::SeqCst` a bajillion times
///
/// default is to increment by 1, second arg can be used to increment by a different value
#[macro_export]
macro_rules! atomic_increment {
    ($atomic:expr) => {
        $atomic.fetch_add(1, Ordering::SeqCst);
    };

    ($atomic:expr, $value:expr) => {
        $atomic.fetch_add($value, Ordering::SeqCst);
    };
}

/// Wrapper around `Atomic*.load` to save me from writing `Ordering::SeqCst` a bajillion times
#[macro_export]
macro_rules! atomic_load {
    ($atomic:expr) => {
        $atomic.load(Ordering::SeqCst)
    };
    ($atomic:expr, $ordering:expr) => {
        $atomic.load($ordering)
    };
}

/// Wrapper around `Atomic*.store` to save me from writing `Ordering::SeqCst` a bajillion times
#[macro_export]
macro_rules! atomic_store {
    ($atomic:expr, $value:expr) => {
        $atomic.store($value, Ordering::SeqCst);
    };
    ($atomic:expr, $value:expr, $ordering:expr) => {
        $atomic.store($value, $ordering);
    };
}
