//! Property tests: invariants that must hold for *any* input.

#![allow(clippy::unwrap_used)] // Panicking is how tests fail.

use jiff::Timestamp;
use proptest::prelude::*;
use trustgraph_core::value::Decimal;
use trustgraph_core::{Keypair, LensOptions, TrustAtom, TrustGraph, Value, credential, reputon};

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
    fn reputon_round_trips(atom in atom(), value in value(), nanos in prop_oneof![Just(0i32), 0i32..1_000_000_000]) {
        // Lossless except for the documented cases: atoms need a value, and
        // content "trust" is the default assertion.
        prop_assume!(atom.content.as_deref() != Some(reputon::DEFAULT_ASSERTION));
        let timestamp = atom.timestamp.map(|t| Timestamp::new(t.as_second(), nanos).unwrap());
        let atom = TrustAtom { value: Some(value), timestamp, ..atom };
        let response = reputon::Response::from_atoms([&atom]).unwrap();
        let json = serde_json::to_string(&response).unwrap();
        let rating = response.reputons[0].rating;
        prop_assert!((0.0..=1.0).contains(&rating));
        let back = reputon::Response::from_json(serde_json::from_str(&json).unwrap()).unwrap().to_atoms().unwrap();
        prop_assert_eq!(back, vec![atom]);
    }

    #[test]
    fn reputon_ratings_are_monotonic(a in value(), b in value()) {
        let (ra, rb) = (reputon::value_to_rating(a), reputon::value_to_rating(b));
        prop_assert_eq!(a.cmp(&b), ra.partial_cmp(&rb).unwrap());
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
