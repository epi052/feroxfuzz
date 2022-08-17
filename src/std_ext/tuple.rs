// the idea to use the tuple_list project and Named/MatchName came directly from the LibAFL team.
// a more comprehensive set of usage/examples can be found there.
use std::ptr::{addr_of, addr_of_mut};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::ObserversList;
        use crate::observers::{Observers, ResponseObserver};
    }
}

/// Used in conjunction with [`MatchName`] to provide a way to do object
/// lookups when iterating through an [`ObserversList`].
///
/// A concrete example can be seen by examining
/// [`Observers`] and [`ResponseObserver`]
pub trait Named {
    /// provide the name of this object
    fn name(&self) -> &str;
}

/// match on an object's name field and return the value
///
/// # Safety
///
/// this operation is unsafe in stable rust, awaiting [specialization](https://stackoverflow.com/a/60138532/7658998)
pub trait MatchName {
    /// match on an object's name field and return a reference to the value
    fn match_name<T>(&self, name: &str) -> Option<&T>;

    /// match on an object's name field and return a mutable reference to the value
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T>;
}

impl MatchName for () {
    fn match_name<T>(&self, _name: &str) -> Option<&T> {
        None
    }
    fn match_name_mut<T>(&mut self, _name: &str) -> Option<&mut T> {
        None
    }
}

impl<Head, Tail> MatchName for (Head, Tail)
where
    Head: Named,
    Tail: MatchName,
{
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        if name == self.0.name() {
            unsafe { (addr_of!(self.0).cast::<T>()).as_ref() }
        } else {
            self.1.match_name::<T>(name)
        }
    }

    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if name == self.0.name() {
            unsafe { (addr_of_mut!(self.0).cast::<T>()).as_mut() }
        } else {
            self.1.match_name_mut::<T>(name)
        }
    }
}
