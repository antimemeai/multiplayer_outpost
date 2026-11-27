//! Strict `@handle` / `@handle:agent` / `@handle's agent` mention detection.
//!
//! Shared between `outpost-mcp` (`party_poll` / `party_wait` `mentioned_self` output)
//! and `outpost-cli` (`mp-outpost chat` `[MENTION]` badge + BEL alert).

use serde_json::Value;

use crate::backend::{McpPartyEvent, McpPartyEventKind};

const fn is_left_boundary_disallowed(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'@')
}

const fn is_right_handle_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}

/// Returns `true` if `text` contains an `@<self_handle>`, `@<self_handle>:agent`,
/// or `@<self_handle>'s agent` mention with strict ASCII word boundaries.
///
/// Rejects email addresses (`foo@handle.com`), domain suffixes (`@handle.com`),
/// handle prefixes (`@handle2`, `@handle_dev`, `@handle-bot`), and `@@handle`.
pub fn text_mentions_handle(text: &str, self_handle: &str) -> bool {
    let handle = self_handle.trim().trim_start_matches('@');
    if handle.is_empty() || !handle.is_ascii() {
        return false;
    }
    let bytes = text.as_bytes();
    let h_bytes = handle.as_bytes();
    let h_len = h_bytes.len();
    if bytes.len() < h_len.saturating_add(1) {
        return false;
    }

    for (i, &b) in bytes.iter().enumerate() {
        if b != b'@' {
            continue;
        }
        // Left boundary: must not be preceded by email-local/word chars (`foo@handle`, `a.b@handle`, `@@handle`).
        if i > 0 {
            let prev_bad = bytes
                .get(i - 1)
                .is_some_and(|&prev| is_left_boundary_disallowed(prev));
            if prev_bad {
                continue;
            }
        }

        let start = i + 1;
        let Some(end) = start.checked_add(h_len) else {
            continue;
        };
        let Some(candidate) = bytes.get(start..end) else {
            continue;
        };
        if !candidate.eq_ignore_ascii_case(h_bytes) {
            continue;
        }

        // Right boundary check.
        match bytes.get(end).copied() {
            None => return true,
            Some(b'.') => {
                // Allow sentence punctuation (`ping @alice.`), reject domains (`@alice.com`).
                let followed_by_alnum = bytes
                    .get(end + 1)
                    .is_some_and(u8::is_ascii_alphanumeric);
                if !followed_by_alnum {
                    return true;
                }
            }
            Some(next) if !is_right_handle_char(next) => {
                // Covers whitespace, punctuation, `:agent`, `'s agent`, `’s agent`, `)`, `,`, `!`, etc.
                return true;
            }
            Some(_) => {}
        }
    }

    false
}

/// Returns `true` if the event sender is the local user (so self echoes never trigger mentions).
pub fn is_self_sender(
    sender_account_id: u64,
    sender_handle: &str,
    self_account_id: Option<u64>,
    self_handle: Option<&str>,
) -> bool {
    if let Some(own_id) = self_account_id
        && own_id != 0
    {
        return sender_account_id != 0 && sender_account_id == own_id;
    }
    if let Some(own_h) = self_handle {
        let own_norm = own_h.trim().trim_start_matches('@');
        let sender_norm = sender_handle.trim().trim_start_matches('@');
        if !own_norm.is_empty() && sender_norm.eq_ignore_ascii_case(own_norm) {
            return true;
        }
    }
    false
}

/// Evaluates whether an incoming `McpPartyEvent` mentions the local user's `@handle`,
/// never matching self echoes or historical catch-up events.
pub fn event_mentions_self(
    ev: &McpPartyEvent,
    self_account_id: Option<u64>,
    self_handle: Option<&str>,
) -> bool {
    if ev.is_historical_catchup {
        return false;
    }
    let Some(handle) = self_handle
        .map(|h| h.trim().trim_start_matches('@'))
        .filter(|h| !h.is_empty())
    else {
        return false;
    };

    match &ev.kind {
        McpPartyEventKind::Chat {
            provenance, body, ..
        } => {
            if is_self_sender(
                provenance.sender_account_id,
                &provenance.sender_handle,
                self_account_id,
                Some(handle),
            ) {
                return false;
            }
            text_mentions_handle(body, handle)
        }
        McpPartyEventKind::BridgeEnvelope {
            provenance,
            payload,
            ..
        } => {
            if is_self_sender(
                provenance.sender_account_id,
                &provenance.sender_handle,
                self_account_id,
                Some(handle),
            ) {
                return false;
            }
            let Ok(text) = core::str::from_utf8(payload) else {
                return false;
            };
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text.trim()) {
                let title_hit = map
                    .get("title")
                    .and_then(Value::as_str)
                    .is_some_and(|t| text_mentions_handle(t, handle));
                let summary_hit = map
                    .get("summary")
                    .and_then(Value::as_str)
                    .is_some_and(|s| text_mentions_handle(s, handle));
                if map.contains_key("title") || map.contains_key("summary") {
                    return title_hit || summary_hit;
                }
            }
            text_mentions_handle(text, handle)
        }
        McpPartyEventKind::ControlNotice {
            provenance, text, ..
        } => {
            if is_self_sender(
                provenance.sender_account_id,
                &provenance.sender_handle,
                self_account_id,
                Some(handle),
            ) {
                return false;
            }
            text_mentions_handle(text, handle)
        }
        McpPartyEventKind::MembershipChanged { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::PeerProvenance;

    #[test]
    fn mention_detection_matches_expected_forms_and_rejects_emails_and_prefixes() {
        for yes in [
            "@alice",
            "@ALICE",
            "hey @alice check this",
            "(@alice) take a look",
            "ping @alice.",
            "yo @alice, ready?",
            "@alice:agent please run tests",
            "@alice's agent fix the lint",
            "@alice\u{2019}s agent check PR",
            "line1\n@alice:agent\nline3",
        ] {
            assert!(
                text_mentions_handle(yes, "alice"),
                "expected mention match for {yes:?}"
            );
            assert!(
                text_mentions_handle(yes, "@alice"),
                "expected mention match with leading @ for {yes:?}"
            );
        }

        for no in [
            "",
            "alice without at",
            "foo@alice.com",
            "first.last@alice.com",
            "a+tag@alice.dev",
            "@alice.com",
            "@alice.rs",
            "@alice2",
            "@alice_dev",
            "@alice-bot",
            "my_@alice",
            "@@alice",
            "user@alice",
        ] {
            assert!(
                !text_mentions_handle(no, "alice"),
                "expected NO mention match for {no:?}"
            );
        }
        assert!(!text_mentions_handle("@alice", ""));
        assert!(!text_mentions_handle("@alice", "@"));
    }

    #[test]
    fn event_mentions_self_ignores_self_echoes_and_checks_cards() {
        let self_prov = PeerProvenance {
            sender_account_id: 1001,
            sender_device_id: 2001,
            sender_handle: "alice".to_string(),
            root_pubkey_fingerprint: String::new(),
            safety_number: String::new(),
            is_browser: false,
            sender_client: "outpost".to_string(),
        };
        let peer_prov = PeerProvenance {
            sender_account_id: 1002,
            sender_device_id: 2002,
            sender_handle: "bob".to_string(),
            root_pubkey_fingerprint: String::new(),
            safety_number: String::new(),
            is_browser: false,
            sender_client: "outpost".to_string(),
        };
        let guest_prov = PeerProvenance {
            sender_account_id: 0,
            sender_device_id: 0,
            sender_handle: "alice".to_string(), // guest reusing name
            root_pubkey_fingerprint: String::new(),
            safety_number: String::new(),
            is_browser: false,
            sender_client: String::new(),
        };
        let browser_self_prov = PeerProvenance {
            sender_account_id: 1001,
            sender_device_id: 0,
            sender_handle: "alice".to_string(),
            root_pubkey_fingerprint: String::new(),
            safety_number: String::new(),
            is_browser: true,
            sender_client: "web".to_string(),
        };

        let self_ev = McpPartyEvent {
            event_seq: 1,
            party_id: 9,
            party_epoch: 1,
            is_historical_catchup: false,
            kind: McpPartyEventKind::Chat {
                provenance: self_prov,
                room_scope: "party/main".to_string(),
                target_selector: "@all".to_string(),
                timestamp_ns: 0,
                body: "@alice talking to myself".to_string(),
            },
        };
        assert!(!event_mentions_self(&self_ev, Some(1001), Some("alice")));

        let peer_ev = McpPartyEvent {
            event_seq: 2,
            party_id: 9,
            party_epoch: 1,
            is_historical_catchup: false,
            kind: McpPartyEventKind::Chat {
                provenance: peer_prov.clone(),
                room_scope: "party/main".to_string(),
                target_selector: "@all".to_string(),
                timestamp_ns: 0,
                body: "hey @alice:agent please check".to_string(),
            },
        };
        assert!(event_mentions_self(&peer_ev, Some(1001), Some("alice")));

        // Historical catch-up event MUST suppress automated mention trigger!
        let mut historical_peer_ev = peer_ev.clone();
        historical_peer_ev.is_historical_catchup = true;
        assert!(!event_mentions_self(
            &historical_peer_ev,
            Some(1001),
            Some("alice")
        ));

        // Guest (account_id 0) mentioning @alice still triggers mention for authenticated alice (1001).
        let guest_ev = McpPartyEvent {
            event_seq: 3,
            party_id: 9,
            party_epoch: 1,
            is_historical_catchup: false,
            kind: McpPartyEventKind::Chat {
                provenance: guest_prov,
                room_scope: "party/main".to_string(),
                target_selector: "@all".to_string(),
                timestamp_ns: 0,
                body: "@alice can you review?".to_string(),
            },
        };
        assert!(event_mentions_self(&guest_ev, Some(1001), Some("alice")));

        // Agent card JSON mentioning @alice in summary triggers mention.
        let card_ev = McpPartyEvent {
            event_seq: 4,
            party_id: 9,
            party_epoch: 1,
            is_historical_catchup: false,
            kind: McpPartyEventKind::BridgeEnvelope {
                provenance: peer_prov,
                room_scope: "party/main".to_string(),
                payload: br#"{"title":"Tests green","summary":"Ready for @alice's agent"}"#
                    .to_vec(),
            },
        };
        assert!(event_mentions_self(&card_ev, Some(1001), Some("alice")));

        // Browser-originated message under the operator's own account/handle does NOT trigger mention.
        let browser_self_ev = McpPartyEvent {
            event_seq: 5,
            party_id: 9,
            party_epoch: 1,
            is_historical_catchup: false,
            kind: McpPartyEventKind::Chat {
                provenance: browser_self_prov,
                room_scope: "party/main".to_string(),
                target_selector: "@all".to_string(),
                timestamp_ns: 0,
                body: "@alice:agent run shell command".to_string(),
            },
        };
        assert!(!event_mentions_self(
            &browser_self_ev,
            Some(1001),
            Some("alice")
        ));
    }
}
