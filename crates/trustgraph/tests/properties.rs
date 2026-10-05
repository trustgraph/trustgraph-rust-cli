//! Property tests: invariants that must hold for *any* input.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use jiff::Timestamp;
use proptest::prelude::*;
use trustgraph::holochain::{Direction, LinkTag};
use trustgraph::value::Decimal;
use trustgraph::{Keypair, LensOptions, TrustAtom, TrustGraph, Value, credential};

fn value() -> impl Strategy<Value = Value> {
    (-1_000_000_000i64..=1_000_000_000).prop_map(|n| Value::new(Decimal::new(n, 9)).unwrap())
}

fn identifier() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9:/._#?=-]{1,40}"
}

fn timestamp() -> impl Strategy<Value = Timestamp> {
    (0i64..4_000_000_000).prop_map(|s| Timestamp::from_second(s).unwrap())
}

fn atom() -> impl Strategy<Value = TrustAtom> {
    (
        identifier(),
        identifier(),
        proptest::option::of("[^\\p{Cc}]{0,60}"),
        proptest::option::of(value()),
        proptest::option::of(timestamp()),
        proptest::collection::btree_map("[a-z]{1,8}", ".{0,20}", 0..3),
    )
        .prop_filter("source and target differ", |(s, t, ..)| s != t)
        .prop_map(|(source, target, content, value, timestamp, extra)| TrustAtom {
            content,
            value,
            timestamp,
            extra,
            ..TrustAtom::new(source, target)
        })
}

proptest! {
    #[test]
    fn value_string_round_trips(v in value()) {
        prop_assert_eq!(v.to_string().parse::<Value>().unwrap(), v);
        let json = serde_json::to_string(&v).unwrap();
        prop_assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), v);
    }

    #[test]
    fn holochain_value_string_is_within_twelve_chars_and_reparses(v in value()) {
        let s = v.to_holochain_string();
        prop_assert!(s.len() <= 12, "{} is too long", s);
        let back: Value = s.parse().unwrap();
        prop_assert!((back.as_f64() - v.as_f64()).abs() <= 1e-9);
    }

    #[test]
    fn values_outside_range_are_rejected(n in prop_oneof![1_000_000_001i64..i64::MAX / 2, i64::MIN / 2..-1_000_000_000]) {
        prop_assert!(Value::new(Decimal::new(n, 9)).is_err());
    }

    #[test]
    fn atom_json_round_trips(atom in atom()) {
        let json = serde_json::to_string(&atom).unwrap();
        prop_assert_eq!(serde_json::from_str::<TrustAtom>(&json).unwrap(), atom);
    }

    #[test]
    fn id_ignores_key_order_and_whitespace(atom in atom()) {
        let pretty = serde_json::to_string_pretty(&atom).unwrap();
        let reparsed: TrustAtom = serde_json::from_str(&pretty).unwrap();
        prop_assert_eq!(reparsed.id().unwrap(), atom.id().unwrap());
    }

    #[test]
    fn credential_round_trips(atom in atom()) {
        let credential = credential::to_credential(&atom).unwrap();
        prop_assert_eq!(credential::from_credential(&credential).unwrap(), atom);
    }

    #[test]
    fn signatures_verify_and_bind_every_byte(atom in atom(), seed in any::<[u8; 32]>(), flip in any::<prop::sample::Index>()) {
        let key = Keypair::from_seed(&seed);
        let atom = TrustAtom { source: key.did().to_string(), ..atom };
        prop_assume!(atom.source != atom.target);
        let signed = credential::sign_atom(&atom, &key, Timestamp::UNIX_EPOCH).unwrap();
        prop_assert_eq!(credential::verify_atom(&signed).unwrap(), atom.clone());

        // Changing the target to any other string must break the signature.
        let mut tampered = signed.clone();
        let target = &atom.target;
        let i = flip.index(target.len());
        let mut bytes = target.clone().into_bytes();
        bytes[i] = if bytes[i] == b'a' { b'b' } else { b'a' };
        tampered["credentialSubject"]["id"] = String::from_utf8(bytes).unwrap().into();
        prop_assert!(credential::verify_atom(&tampered).is_err());
    }

    #[test]
    fn holochain_tags_round_trip(atom in atom(), reverse in any::<bool>(), bucket in "[0-9]{9}") {
        let direction = if reverse { Direction::Reverse } else { Direction::Forward };
        let tag = LinkTag::for_atom(&atom, direction, Some(bucket), None);
        if let Ok(bytes) = tag.encode() {
            let decoded = LinkTag::decode(&bytes).unwrap();
            prop_assert_eq!(decoded.direction, direction);
            prop_assert_eq!(decoded.content.clone(), atom.content.clone().filter(|c| !c.is_empty()));
            prop_assert_eq!(decoded.bucket.clone(), tag.bucket);
            let (base, target) = if reverse { (&atom.target, &atom.source) } else { (&atom.source, &atom.target) };
            let rebuilt = decoded.to_atom(base, target);
            prop_assert_eq!(&rebuilt.source, &atom.source);
            prop_assert_eq!(&rebuilt.target, &atom.target);
        }
    }

    #[test]
    fn lens_scores_are_bounded_and_root_is_never_scored(
        edges in proptest::collection::vec((0u8..6, 0u8..6, value()), 0..40),
        depth in 1usize..6,
        decay in 0.0f64..=1.0,
    ) {
        let atoms: Vec<TrustAtom> = edges
            .into_iter()
            .filter(|(s, t, _)| s != t)
            .map(|(s, t, v)| TrustAtom::new(format!("agent{s}"), format!("agent{t}")).with_value(v))
            .collect();
        let graph: TrustGraph = atoms.iter().collect();
        let entries = graph.lens("agent0", &LensOptions { depth, decay, topic: None });
        for entry in &entries {
            prop_assert!((-1.0..=1.0).contains(&entry.score));
            prop_assert!((0.0..=1.0).contains(&entry.confidence));
            prop_assert!(entry.hops >= 1 && entry.hops <= depth);
            prop_assert_ne!(&entry.target, "agent0");
        }
        let mut targets: Vec<_> = entries.iter().map(|e| &e.target).collect();
        targets.dedup();
        prop_assert_eq!(targets.len(), entries.len());
    }
}
