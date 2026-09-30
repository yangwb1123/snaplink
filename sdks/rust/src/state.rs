use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::SnaplinkError;

/// Atomic short-lived transaction storage.
pub trait StateStore: Send + Sync {
    fn take(&self, key: &str) -> Result<Option<Vec<u8>>, SnaplinkError>;
    fn save(&self, key: &str, value: &[u8]) -> Result<(), SnaplinkError>;
}

/// In-process state storage for development and single-process examples.
#[derive(Clone, Default)]
pub struct MemoryStateStore {
    values: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemoryStateStore {
    fn take(&self, key: &str) -> Result<Option<Vec<u8>>, SnaplinkError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| SnaplinkError::State("state store lock was poisoned".into()))?;
        Ok(values.remove(key))
    }

    fn save(&self, key: &str, value: &[u8]) -> Result<(), SnaplinkError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| SnaplinkError::State("state store lock was poisoned".into()))?;
        values.insert(key.to_owned(), value.to_vec());
        Ok(())
    }
}
