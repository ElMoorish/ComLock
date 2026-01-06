//! Decoy Vault for ComLock
//!
//! Pre-generated innocent content displayed after duress wipe.
//! This creates plausible deniability by showing "normal" app usage.

use serde::{Deserialize, Serialize};

// ============================================================================
// DECOY DATA STRUCTURES
// ============================================================================

/// A decoy contact shown in duress mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyContact {
    pub id: String,
    pub name: String,
    pub avatar_letter: char,
    pub last_message: String,
    pub last_message_time: String,
}

/// A decoy message shown in duress mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyMessage {
    pub id: String,
    pub text: String,
    pub sent: bool,
    pub time: String,
}

/// A decoy conversation (contact + messages)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConversation {
    pub contact: DecoyContact,
    pub messages: Vec<DecoyMessage>,
}

/// The complete decoy vault
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecoyVault {
    pub conversations: Vec<DecoyConversation>,
}

// ============================================================================
// PRE-GENERATED DECOY CONTENT
// ============================================================================

impl DecoyVault {
    /// Load pre-generated decoy content
    pub fn load_default() -> Self {
        Self {
            conversations: vec![
                // Mom conversation
                DecoyConversation {
                    contact: DecoyContact {
                        id: "decoy_1".into(),
                        name: "Mom".into(),
                        avatar_letter: 'M',
                        last_message: "Love you too! 💕".into(),
                        last_message_time: "2:30 PM".into(),
                    },
                    messages: vec![
                        DecoyMessage {
                            id: "m1".into(),
                            text: "Hey sweetie, don't forget we're having dinner on Sunday!".into(),
                            sent: false,
                            time: "10:15 AM".into(),
                        },
                        DecoyMessage {
                            id: "m2".into(),
                            text: "I'll be there! Should I bring anything?".into(),
                            sent: true,
                            time: "10:20 AM".into(),
                        },
                        DecoyMessage {
                            id: "m3".into(),
                            text: "Just yourself! Dad is making his famous lasagna".into(),
                            sent: false,
                            time: "10:22 AM".into(),
                        },
                        DecoyMessage {
                            id: "m4".into(),
                            text: "Yum! Can't wait 😊".into(),
                            sent: true,
                            time: "10:25 AM".into(),
                        },
                        DecoyMessage {
                            id: "m5".into(),
                            text: "Love you too! 💕".into(),
                            sent: false,
                            time: "2:30 PM".into(),
                        },
                    ],
                },
                // Work Group conversation
                DecoyConversation {
                    contact: DecoyContact {
                        id: "decoy_2".into(),
                        name: "Work Team".into(),
                        avatar_letter: 'W',
                        last_message: "Sounds good, see you then!".into(),
                        last_message_time: "4:45 PM".into(),
                    },
                    messages: vec![
                        DecoyMessage {
                            id: "w1".into(),
                            text: "Team meeting moved to 3pm tomorrow".into(),
                            sent: false,
                            time: "3:30 PM".into(),
                        },
                        DecoyMessage {
                            id: "w2".into(),
                            text: "Thanks for the heads up!".into(),
                            sent: true,
                            time: "3:35 PM".into(),
                        },
                        DecoyMessage {
                            id: "w3".into(),
                            text: "No problem. Conference room B".into(),
                            sent: false,
                            time: "3:36 PM".into(),
                        },
                        DecoyMessage {
                            id: "w4".into(),
                            text: "Sounds good, see you then!".into(),
                            sent: true,
                            time: "4:45 PM".into(),
                        },
                    ],
                },
                // Friend conversation
                DecoyConversation {
                    contact: DecoyContact {
                        id: "decoy_3".into(),
                        name: "Alex".into(),
                        avatar_letter: 'A',
                        last_message: "Haha definitely! Talk soon".into(),
                        last_message_time: "Yesterday".into(),
                    },
                    messages: vec![
                        DecoyMessage {
                            id: "a1".into(),
                            text: "Hey! Thanks for lunch yesterday, it was great catching up"
                                .into(),
                            sent: false,
                            time: "6:00 PM".into(),
                        },
                        DecoyMessage {
                            id: "a2".into(),
                            text: "Same here! We should do it more often".into(),
                            sent: true,
                            time: "6:15 PM".into(),
                        },
                        DecoyMessage {
                            id: "a3".into(),
                            text: "For sure! Maybe try that new Thai place next time?".into(),
                            sent: false,
                            time: "6:20 PM".into(),
                        },
                        DecoyMessage {
                            id: "a4".into(),
                            text: "I love Thai food! Count me in".into(),
                            sent: true,
                            time: "6:25 PM".into(),
                        },
                        DecoyMessage {
                            id: "a5".into(),
                            text: "Haha definitely! Talk soon".into(),
                            sent: false,
                            time: "6:30 PM".into(),
                        },
                    ],
                },
                // Grocery list conversation
                DecoyConversation {
                    contact: DecoyContact {
                        id: "decoy_4".into(),
                        name: "Shopping List".into(),
                        avatar_letter: '🛒',
                        last_message: "Eggs, bread, cheese".into(),
                        last_message_time: "Mon".into(),
                    },
                    messages: vec![
                        DecoyMessage {
                            id: "s1".into(),
                            text: "Milk".into(),
                            sent: true,
                            time: "8:00 AM".into(),
                        },
                        DecoyMessage {
                            id: "s2".into(),
                            text: "Eggs".into(),
                            sent: true,
                            time: "8:01 AM".into(),
                        },
                        DecoyMessage {
                            id: "s3".into(),
                            text: "Bread".into(),
                            sent: true,
                            time: "8:01 AM".into(),
                        },
                        DecoyMessage {
                            id: "s4".into(),
                            text: "Cheese".into(),
                            sent: true,
                            time: "8:02 AM".into(),
                        },
                        DecoyMessage {
                            id: "s5".into(),
                            text: "Apples".into(),
                            sent: true,
                            time: "8:02 AM".into(),
                        },
                    ],
                },
            ],
        }
    }

    /// Get all decoy contacts for display
    pub fn get_contacts(&self) -> Vec<DecoyContact> {
        self.conversations
            .iter()
            .map(|c| c.contact.clone())
            .collect()
    }

    /// Get messages for a specific decoy contact
    pub fn get_messages(&self, contact_id: &str) -> Vec<DecoyMessage> {
        self.conversations
            .iter()
            .find(|c| c.contact.id == contact_id)
            .map(|c| c.messages.clone())
            .unwrap_or_default()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_vault_load() {
        let vault = DecoyVault::load_default();

        assert!(!vault.conversations.is_empty());
        assert!(vault.conversations.len() >= 3);
    }

    #[test]
    fn test_get_contacts() {
        let vault = DecoyVault::load_default();
        let contacts = vault.get_contacts();

        assert!(!contacts.is_empty());
        assert!(contacts.iter().any(|c| c.name == "Mom"));
    }

    #[test]
    fn test_get_messages() {
        let vault = DecoyVault::load_default();
        let messages = vault.get_messages("decoy_1");

        assert!(!messages.is_empty());
        assert!(messages.iter().any(|m| m.text.contains("dinner")));
    }

    #[test]
    fn test_messages_for_invalid_contact() {
        let vault = DecoyVault::load_default();
        let messages = vault.get_messages("nonexistent");

        assert!(messages.is_empty());
    }
}
