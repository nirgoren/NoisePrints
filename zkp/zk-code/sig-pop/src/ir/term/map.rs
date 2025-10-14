//! A map type

use super::*;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// An IR map value.
pub struct Map {
    /// Key sort
    pub key_sort: Sort,
    /// Value sort
    pub value_sort: Sort,
    /// Key-> Value map
    pub map: FxHashMap<Value, Value>,
}

impl Map {
    /// Crate a new map from {key,value} sorts and items.
    pub fn new(
        key_sort: Sort,
        value_sort: Sort,
        items: impl IntoIterator<Item = (Value, Value)>,
    ) -> Map {
        let this = Map {
            key_sort,
            value_sort,
            map: items.into_iter().collect(),
        };
        for (k, v) in &this.map {
            debug_assert_eq!(k.sort(), this.key_sort);
            debug_assert_eq!(v.sort(), this.value_sort);
        }
        this
    }
    /// Select
    pub fn select(&self, key: &Value) -> Value {
        self.map
            .get(key)
            .cloned()
            .unwrap_or_else(|| self.value_sort.default_value())
    }
    /// Check for a key
    pub fn contains_key(&self, key: &Value) -> bool {
        self.map.contains_key(key)
    }
}

impl std::cmp::PartialOrd for Map {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let mut this: Vec<_> = self.map.iter().collect();
        let mut other: Vec<_> = other.map.iter().collect();
        this.sort();
        other.sort();
        this.partial_cmp(&other)
    }
}
impl std::hash::Hash for Map {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut this: Vec<_> = self.map.iter().collect();
        this.sort();
        this.hash(state);
    }
}
