use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// this implementation is a mix of the two examples below:
// - https://willcrichton.net/rust-api-type-patterns/registries.html
// - https://refactoring.guru/design-patterns/observer/rust/example

/// Unique identifier associated with a listener of a particular event type
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenerId(usize);

/// mapping of event types to subscribers
///
/// `TypeId` allows us to get a unique, hashable identifier for each type.
/// `Any` allows us to up-cast/down-cast objects at runtime. Hence, our
/// `TypeMap` will map from `TypeId` to `Box<dyn Any>`.
#[derive(Debug)]
struct TypeMap {
    inner: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl TypeMap {
    /// associate a type `T` with a `value` wrapped in a `Box`
    fn set<T>(&mut self, value: T)
    where
        T: Any + 'static + Send + Sync,
    {
        self.inner.insert(TypeId::of::<T>(), Box::new(value));
    }

    /// determine if the `TypeMap` contains a value for type `T`
    fn has<T>(&self) -> bool
    where
        T: Any + 'static + Send + Sync,
    {
        self.inner.contains_key(&TypeId::of::<T>())
    }

    /// get a reference to the value associated with type `T`
    fn get<T>(&self) -> Option<&T>
    where
        T: Any + 'static + Send + Sync,
    {
        self.inner
            .get(&TypeId::of::<T>())
            .map(|t| t.downcast_ref::<T>().unwrap())
    }

    /// get a mutable reference to the value associated with type `T`
    fn get_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Any + 'static + Send + Sync,
    {
        self.inner
            .get_mut(&TypeId::of::<T>())
            .map(|t| t.downcast_mut::<T>().unwrap())
    }
}

/// trait for the publisher side of the observer pattern
///
/// made a trait so that we can impl it on an `Arc<RwLock<..>>`
pub trait EventPublisher {
    /// subscribe to an event of type `E` where the listener accepts a reference to `E`
    /// as its only argument and returns nothing
    fn subscribe<E>(&mut self, listener: impl Fn(E) + 'static + Send + Sync) -> Option<ListenerId>
    where
        E: 'static;

    /// unsubscribe from an event of type `E` via the `ListenerId` returned by `subscribe`
    fn unsubscribe<E>(&mut self, identifier: ListenerId)
    where
        E: 'static;

    /// notify all listeners of an event of type `E`
    fn notify<E>(&self, event: E)
    where
        E: 'static + Clone;

    /// determine if there are any listeners for an event of type `E`
    fn has_listeners<E>(&self) -> bool
    where
        E: 'static;
}

/// type alias for a subscriber function
type Subscriber<E> = dyn Fn(E) + 'static + Send + Sync;

/// type alias for a vector of subscribers
type ListenerVec<E> = Vec<Box<Subscriber<E>>>;

/// publisher side of the observer pattern
#[derive(Debug)]
pub struct Publisher {
    registry: TypeMap,
}

impl Default for Publisher {
    fn default() -> Self {
        Self {
            registry: TypeMap {
                inner: HashMap::new(),
            },
        }
    }
}

impl Publisher {
    /// create a new [`Publisher`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl EventPublisher for Publisher {
    fn subscribe<E>(&mut self, listener: impl Fn(E) + 'static + Send + Sync) -> Option<ListenerId>
    where
        E: 'static,
    {
        if !self.registry.has::<ListenerVec<E>>() {
            self.registry.set::<ListenerVec<E>>(Vec::new());
        }

        let listeners = self.registry.get_mut::<ListenerVec<E>>().unwrap();
        listeners.push(Box::new(listener));
        Some(ListenerId(listeners.len() - 1))
    }

    fn unsubscribe<E>(&mut self, identifier: ListenerId)
    where
        E: 'static,
    {
        if let Some(listeners) = self.registry.get_mut::<ListenerVec<E>>() {
            let _listener = listeners.remove(identifier.0);

            if listeners.is_empty() {
                self.registry.inner.remove(&TypeId::of::<ListenerVec<E>>());
            }
        }
    }

    #[inline]
    fn notify<E>(&self, event: E)
    where
        E: 'static + Clone,
    {
        if let Some(listeners) = self.registry.get::<ListenerVec<E>>() {
            for callback in listeners {
                callback(event.clone());
            }
        }
    }

    #[inline]
    fn has_listeners<E>(&self) -> bool
    where
        E: 'static,
    {
        self.registry
            .get::<ListenerVec<E>>()
            .is_some_and(|listeners| !listeners.is_empty())
    }
}

impl EventPublisher for Arc<RwLock<Publisher>> {
    fn subscribe<E>(&mut self, listener: impl Fn(E) + 'static + Send + Sync) -> Option<ListenerId>
    where
        E: 'static,
    {
        if let Ok(mut guard) = self.write() {
            return guard.subscribe(listener);
        }

        None
    }

    fn unsubscribe<E>(&mut self, identifier: ListenerId)
    where
        E: 'static,
    {
        if let Ok(mut guard) = self.write() {
            guard.unsubscribe::<E>(identifier);
        }
    }

    #[inline]
    fn notify<E>(&self, event: E)
    where
        E: 'static + Clone,
    {
        if let Ok(guard) = self.read() {
            guard.notify(event);
        }
    }

    #[inline]
    fn has_listeners<E>(&self) -> bool
    where
        E: 'static,
    {
        self.read().is_ok_and(|guard| guard.has_listeners::<E>())
    }
}

#[cfg(test)]
mod tests {
    use crate::events::FuzzNTimes;

    use super::*;

    #[test]
    fn test_publisher() {
        fn test_fn(event: FuzzNTimes) {
            assert_eq!(event.iterations, 10);
        }

        let mut publisher = Publisher::new();

        let listener_id = publisher.subscribe(test_fn).unwrap();

        assert!(publisher.registry.has::<ListenerVec<FuzzNTimes>>());
        assert!(publisher
            .registry
            .get::<ListenerVec<FuzzNTimes>>()
            .is_some());
        assert!(publisher
            .registry
            .get_mut::<ListenerVec<FuzzNTimes>>()
            .is_some());

        publisher.notify(FuzzNTimes { iterations: 10 });

        publisher.unsubscribe::<FuzzNTimes>(listener_id);

        assert!(publisher
            .registry
            .get::<ListenerVec<FuzzNTimes>>()
            .is_none());
        assert!(!publisher.has_listeners::<FuzzNTimes>());
    }
}
