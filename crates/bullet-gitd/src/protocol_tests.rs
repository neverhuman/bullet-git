//! Protocol frame unit proofs.

use super::*;
use std::io::Cursor;

#[test]
fn frame_reader_is_bounded_and_keeps_frame_boundaries() {
    let mut input = Cursor::new(b"one\ntwo\n".to_vec());
    assert_eq!(read_frame(&mut input).unwrap().as_deref(), Some("one"));
    assert_eq!(read_frame(&mut input).unwrap().as_deref(), Some("two"));
    assert!(read_frame(&mut input).unwrap().is_none());

    let mut oversized = Cursor::new(vec![b'x'; MAX_FRAME_BYTES + 1]);
    let error = read_frame(&mut oversized).expect_err("oversized refused");
    assert_eq!(error.reason_code(), "FRAME_TOO_LARGE");

    let mut invalid = Cursor::new(vec![0xff, b'\n']);
    let error = read_frame(&mut invalid).expect_err("invalid UTF-8 refused");
    assert_eq!(error.reason_code(), "INVALID_UTF8");
}

use bullet_git_types::{MAX_CONTENT_BYTES, MAX_PATCH_OPERATIONS};

/// A 4 KiB path (the `RepoPath` maximum) with a distinct top segment so
/// no operation contains another.
fn long_path(index: usize) -> String {
    let head = format!("d{index:03}/");
    format!("{head}{}", "p".repeat(4_096 - head.len()))
}

/// The largest request the shared bounds admit: every operation slot
/// used at the path maximum, and the full 32 MiB aggregate spread over
/// 32 maximal write bodies made of `fill`; the remaining slots delete.
fn maximal_proposal(fill: char) -> Value {
    let body: String = std::iter::repeat_n(fill, MAX_CONTENT_BYTES).collect();
    let writes = MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES;
    let operations: Vec<Value> = (0..MAX_PATCH_OPERATIONS)
        .map(|index| {
            if index < writes {
                json!({
                    "path": long_path(index),
                    "preimage": {"kind": "absent"},
                    "mutation": {"kind": "write", "content_utf8": body},
                })
            } else {
                json!({
                    "path": long_path(index),
                    "preimage": {"kind": "digest", "digest": "7".repeat(64)},
                    "mutation": {"kind": "delete"},
                })
            }
        })
        .collect();
    json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "operations": operations,
        "gate_ids": [format!("gat_{}", "5".repeat(64))],
    })
}

fn request_line(method: &str, params: Value) -> String {
    json!({
        "id": 1,
        "method": method,
        "token": {"attempt_id": format!("atm_{}", "2".repeat(64)), "attempt_fence": 7},
        "params": params,
    })
    .to_string()
}

fn framed(line: &str) -> Request {
    let mut input = Cursor::new(format!("{line}\n").into_bytes());
    let frame = read_frame(&mut input)
        .expect("frame within bound")
        .expect("one frame");
    serde_json::from_str(&frame).expect("request decodes")
}

#[test]
fn frame_bound_is_derived_from_the_shared_aggregate_bound() {
    assert_eq!(MAX_AGGREGATE_CONTENT_BYTES, 32 * 1_048_576);
    assert_eq!(MAX_FRAME_BYTES, 65 * 1_048_576);

    let mut exact = Cursor::new([vec![b'x'; MAX_FRAME_BYTES], vec![b'\n']].concat());
    let frame = read_frame(&mut exact).expect("exact bound admitted");
    assert_eq!(frame.map(|text| text.len()), Some(MAX_FRAME_BYTES));

    let mut over = Cursor::new([vec![b'x'; MAX_FRAME_BYTES + 1], vec![b'\n']].concat());
    let error = read_frame(&mut over).expect_err("one byte over refused");
    assert_eq!(error.reason_code(), "FRAME_TOO_LARGE");
}

#[test]
fn maximal_apply_proposal_crosses_the_frame_and_one_byte_more_is_refused() {
    // Printable bodies: the aggregate crosses the frame with room to spare.
    let plain = request_line("apply_proposal", json!({"proposal": maximal_proposal('x')}));
    assert!(plain.len() <= MAX_FRAME_BYTES, "{} bytes", plain.len());
    let request = framed(&plain);
    assert_eq!(request.method, "apply_proposal");
    let params: ApplyProposalParams =
        serde_json::from_value(request.params).expect("maximal proposal decodes");
    params
        .proposal
        .validate()
        .expect("exactly the aggregate is admitted");
    let aggregate: usize = params
        .proposal
        .operations
        .iter()
        .filter_map(|operation| match &operation.mutation {
            bullet_git_types::PatchMutation::Write { content_utf8 } => Some(content_utf8.len()),
            bullet_git_types::PatchMutation::Delete => None,
        })
        .sum();
    assert_eq!(aggregate, MAX_AGGREGATE_CONTENT_BYTES);

    // Worst two-byte escaping: every content byte is a quote.
    let escaped = request_line("apply_proposal", json!({"proposal": maximal_proposal('"')}));
    assert!(
        escaped.len() > 2 * MAX_AGGREGATE_CONTENT_BYTES,
        "{} bytes",
        escaped.len()
    );
    assert!(escaped.len() <= MAX_FRAME_BYTES, "{} bytes", escaped.len());
    framed(&escaped);

    // One content byte over the aggregate: framed, then typed refusal.
    let mut over = maximal_proposal('x');
    over["operations"][MAX_PATCH_OPERATIONS - 1] = json!({
        "path": long_path(MAX_PATCH_OPERATIONS - 1),
        "preimage": {"kind": "absent"},
        "mutation": {"kind": "write", "content_utf8": "y"},
    });
    let line = request_line("apply_proposal", json!({"proposal": over}));
    assert!(line.len() <= MAX_FRAME_BYTES);
    let params: ApplyProposalParams =
        serde_json::from_value(framed(&line).params).expect("decodes");
    let error = params
        .proposal
        .validate()
        .expect_err("aggregate + 1 refused");
    assert_eq!(error.reason_code(), "AGGREGATE_CONTENT_TOO_LARGE");
}

#[test]
fn maximal_hex_apply_change_crosses_the_frame() {
    let body = "ab".repeat(MAX_CONTENT_BYTES);
    let writes = MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES;
    let patches: Vec<Value> = (0..MAX_PATCH_OPERATIONS)
        .map(|index| {
            if index < writes {
                json!({"path": long_path(index), "contents_hex": body})
            } else {
                json!({"path": long_path(index), "op": "delete"})
            }
        })
        .collect();
    let line = request_line("apply_change", json!({"patches": patches}));
    assert!(line.len() > 2 * MAX_AGGREGATE_CONTENT_BYTES);
    assert!(line.len() <= MAX_FRAME_BYTES, "{} bytes", line.len());
    let params: ApplyParams = serde_json::from_value(framed(&line).params).expect("decodes");
    assert_eq!(params.patches.len(), MAX_PATCH_OPERATIONS);
    let decoded: usize = params
        .patches
        .iter()
        .filter_map(|patch| patch.contents_hex.as_ref())
        .map(|hex_text| hex_text.len() / 2)
        .sum();
    assert_eq!(decoded, MAX_AGGREGATE_CONTENT_BYTES);
}

#[test]
fn apply_proposal_params_deny_legacy_and_model_fields() {
    let proposal = json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "4".repeat(64),
        "operations": [{
            "path": "src/lib.rs",
            "preimage": {"kind": "absent"},
            "mutation": {"kind": "write", "content_utf8": "next"}
        }],
        "gate_ids": [format!("gat_{}", "5".repeat(64))]
    });
    let decoded: ApplyProposalParams =
        serde_json::from_value(json!({"proposal": proposal.clone()})).expect("canonical");
    decoded.proposal.validate().expect("semantic validation");

    let mut proposal_with_comment = proposal.clone();
    proposal_with_comment["intent_summary"] = json!("model text");
    for bad in [
        json!({"proposal": proposal.clone(), "patches": []}),
        json!({"proposal": proposal_with_comment}),
    ] {
        assert!(
            serde_json::from_value::<ApplyProposalParams>(bad).is_err(),
            "non-canonical params accepted"
        );
    }
}
