use serde::{Deserialize, Serialize};

/// Metadata safe to return to a host for local notification handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NotificationEvent {
    pub event_id: [u8; 32],
    pub kind: NotificationKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NotificationKind {
    NewLike,
    NewMatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NotificationPreferences {
    pub likes_enabled: bool,
    pub matches_enabled: bool,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            likes_enabled: true,
            matches_enabled: true,
        }
    }
}
