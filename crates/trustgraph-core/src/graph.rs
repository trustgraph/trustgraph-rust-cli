//! Agent-centric trust graphs: the **Agent Lens** and **Trust Cascade**.
//!
//! There is no global reputation score in Trust Graph. Every agent sees the
//! world through their own *lens*: their direct ratings, plus ratings made
//! by the agents they trust, plus ratings made by the agents *those* agents
//! trust, and so on. Each extra hop counts for less: this is the *cascade*.
//!
//! # Algorithm
//!
//! 1. **Edges.** Only atoms with a value are used. If a `topic` is given,
//!    only atoms about that topic are used, for both passing trust along and
//!    for the final rating: trusting someone about sushi says nothing about
//!    their taste in software. If one source rated the same target several
//!    times, the latest rating per content wins, and ratings with different
//!    contents are averaged.
//! 2. **Reach.** Starting from the root agent (weight 1), trust flows along
//!    *positive* edges only. The weight of an agent is the strongest path to
//!    it: the product of the edge values along the path, times `decay` for
//!    each hop after the first. Distrust is never passed along: you can see
//!    who your friends distrust, but not who the people they distrust trust.
//! 3. **Scores.** A target rated directly by the root gets the root's own
//!    rating. Otherwise its score is the average of the ratings made by
//!    agents the root can reach, weighted by each rater's weight (times
//!    `decay`). `confidence` is the weight of the most trusted rater.
//!
//! Only paths of at most `depth` hops, counting the final rating, are used.

use std::collections::{BTreeMap, HashMap};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::atom::content_matches_topic;
use crate::{Result, TrustAtom, Value};

/// Options for [`TrustGraph::lens`].
#[derive(Debug, Clone, PartialEq)]
pub struct LensOptions {
    /// Maximum number of hops from the root to a rated target. `1` means
    /// direct ratings only.
    pub depth: usize,
    /// How much each hop after the first counts, in `0..=1`.
    pub decay: f64,
    /// If set, only use atoms about this topic.
    pub topic: Option<String>,
}

impl Default for LensOptions {
    fn default() -> Self {
        Self { depth: 3, decay: 0.5, topic: None }
    }
}

/// One target as seen through an agent's lens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensEntry {
    /// The target being scored.
    pub target: String,
    /// The score, in `-1..=1`.
    pub score: f64,
    /// How strongly the root trusts the most trusted rater (1 for a direct
    /// rating), in `0..=1`.
    pub confidence: f64,
    /// Number of hops from the root to the closest rating.
    pub hops: usize,
    /// Number of agents whose ratings were combined.
    pub raters: usize,
}

/// `target → content → (timestamp, value)`: one source's latest ratings.
type Ratings = BTreeMap<String, BTreeMap<String, (Option<Timestamp>, Value)>>;

/// A set of Trust Atoms, indexed for lens queries.
#[derive(Debug, Clone, Default)]
pub struct TrustGraph {
    /// `source → target → content → (timestamp, value)`, latest rating only.
    ratings: HashMap<String, Ratings>,
}

impl TrustGraph {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an atom. Atoms without a value are ignored. Of two atoms with
    /// the same source, target and content, the later one (by timestamp,
    /// then by insertion order) wins.
    pub fn insert(&mut self, atom: &TrustAtom) {
        let Some(value) = atom.value else { return };
        let slot = self
            .ratings
            .entry(atom.source.clone())
            .or_default()
            .entry(atom.target.clone())
            .or_default()
            .entry(atom.content.clone().unwrap_or_default());
        match slot {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert((atom.timestamp, value));
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                if atom.timestamp >= e.get().0 {
                    e.insert((atom.timestamp, value));
                }
            }
        }
    }

    /// Number of distinct (source, target, content) ratings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ratings.values().flat_map(BTreeMap::values).map(BTreeMap::len).sum()
    }

    /// True if the graph has no ratings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The edges out of `source` for `topic`: `target → averaged value`.
    fn edges(&self, source: &str, topic: Option<&str>) -> BTreeMap<&str, f64> {
        let mut out = BTreeMap::new();
        let Some(targets) = self.ratings.get(source) else {
            return out;
        };
        for (target, by_content) in targets {
            let values: Vec<f64> = by_content
                .iter()
                .filter(|(content, _)| topic.is_none_or(|t| content_matches_topic(content, t)))
                .map(|(_, (_, value))| value.as_f64())
                .collect();
            if !values.is_empty() {
                #[allow(clippy::cast_precision_loss)]
                out.insert(target.as_str(), values.iter().sum::<f64>() / values.len() as f64);
            }
        }
        out
    }

    /// Everything `root` can see, best first (highest score, then highest
    /// confidence, then target).
    #[must_use]
    pub fn lens(&self, root: &str, options: &LensOptions) -> Vec<LensEntry> {
        let topic = options.topic.as_deref();
        let decay = options.decay.clamp(0.0, 1.0);
        if options.depth == 0 {
            return Vec::new();
        }

        // Each source's edges, computed once (each round revisits agents).
        let edges: HashMap<&str, BTreeMap<&str, f64>> =
            self.ratings.keys().map(|source| (source.as_str(), self.edges(source, topic))).collect();
        let no_edges = BTreeMap::new();
        let edges_of = |agent: &str| edges.get(agent).unwrap_or(&no_edges);

        // Reach: best weight to each agent using at most depth - 1 hops
        // (bounded Bellman-Ford, maximizing the product of weights).
        let mut reach: BTreeMap<&str, (f64, usize)> = BTreeMap::from([(root, (1.0, 0))]);
        for hop in 1..options.depth {
            // Relax from the previous round's snapshot so paths grow by at most one hop per round.
            let mut next = reach.clone();
            for (&agent, &(weight, _)) in &reach {
                let factor = if agent == root { 1.0 } else { decay };
                for (&target, &value) in edges_of(agent) {
                    if value <= 0.0 || target == root {
                        continue;
                    }
                    let candidate = weight * value * factor;
                    // Exact float equality is intended: it only breaks exact ties.
                    #[allow(clippy::float_cmp)]
                    let better = next.get(target).is_none_or(|&(w, h)| candidate > w || (candidate == w && hop < h));
                    if better {
                        next.insert(target, (candidate, hop));
                    }
                }
            }
            if next == reach {
                break;
            }
            reach = next;
        }

        // Scores.
        let direct = edges_of(root);
        let mut sums: BTreeMap<&str, (f64, f64, f64, usize, usize)> = BTreeMap::new(); // (Σw·v, Σw, max w, min hops, raters)
        for (&agent, &(weight, hops)) in &reach {
            if agent == root || weight <= 0.0 {
                continue;
            }
            let voice = weight * decay;
            if voice <= 0.0 {
                continue;
            }
            for (&target, &value) in edges_of(agent) {
                if target == root || direct.contains_key(target) {
                    continue;
                }
                let e = sums.entry(target).or_insert((0.0, 0.0, 0.0, usize::MAX, 0));
                e.0 += voice * value;
                e.1 += voice;
                e.2 = e.2.max(voice);
                e.3 = e.3.min(hops + 1);
                e.4 += 1;
            }
        }

        let mut entries: Vec<LensEntry> = direct
            .iter()
            .map(|(&target, &value)| LensEntry {
                target: target.to_owned(),
                score: round9(value),
                confidence: 1.0,
                hops: 1,
                raters: 1,
            })
            .chain(sums.into_iter().map(|(target, (weighted, total, max, hops, raters))| LensEntry {
                target: target.to_owned(),
                score: round9((weighted / total).clamp(-1.0, 1.0)),
                confidence: round9(max),
                hops,
                raters,
            }))
            .collect();
        entries.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then(b.confidence.total_cmp(&a.confidence))
                .then_with(|| a.target.cmp(&b.target))
        });
        entries
    }

    /// Turns lens results into *rollup* atoms: cached trust, from the root's
    /// point of view, that can be stored and shared like any other atom.
    /// Each rollup is marked with `extra.rollup = "agent-lens"`, the
    /// parameters used, and the entry's `confidence` and number of `raters`.
    ///
    /// # Errors
    ///
    /// Fails only if a score is not finite, which `lens` never produces.
    pub fn rollup(root: &str, entries: &[LensEntry], options: &LensOptions, at: Timestamp) -> Result<Vec<TrustAtom>> {
        entries
            .iter()
            .map(|entry| {
                let mut atom = TrustAtom::new(root, &entry.target)
                    .with_value(Value::from_f64(entry.score)?)
                    .with_timestamp(at)
                    .with_extra("rollup", "agent-lens")
                    .with_extra("depth", options.depth.to_string())
                    .with_extra("decay", options.decay.to_string())
                    .with_extra("confidence", format!("{:.6}", entry.confidence))
                    .with_extra("raters", entry.raters.to_string());
                atom.content.clone_from(&options.topic);
                Ok(atom)
            })
            .collect()
    }
}

impl<'a> FromIterator<&'a TrustAtom> for TrustGraph {
    fn from_iter<I: IntoIterator<Item = &'a TrustAtom>>(iter: I) -> Self {
        let mut graph = Self::new();
        for atom in iter {
            graph.insert(atom);
        }
        graph
    }
}

/// Rounds to nine decimal places (the precision of a [`Value`]), hiding
/// floating-point noise such as `0.18000000000000002`.
fn round9(x: f64) -> f64 {
    (x * 1e9).round() / 1e9
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(source: &str, target: &str, value: &str) -> TrustAtom {
        TrustAtom::new(source, target).with_value(value.parse().unwrap())
    }

    fn about(source: &str, target: &str, value: &str, topic: &str) -> TrustAtom {
        rate(source, target, value).with_content(topic)
    }

    fn lens(atoms: &[TrustAtom], root: &str, options: &LensOptions) -> BTreeMap<String, LensEntry> {
        atoms.iter().collect::<TrustGraph>().lens(root, options).into_iter().map(|e| (e.target.clone(), e)).collect()
    }

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn direct_ratings_are_returned_as_is() {
        let out =
            lens(&[rate("alice", "bob", "0.8"), rate("alice", "carol", "-0.5")], "alice", &LensOptions::default());
        assert!(close(out["bob"].score, 0.8));
        assert!(close(out["bob"].confidence, 1.0));
        assert_eq!(out["bob"].hops, 1);
        assert!(close(out["carol"].score, -0.5));
    }

    #[test]
    fn trust_cascades_with_decay() {
        let atoms = [rate("alice", "bob", "0.8"), rate("bob", "carol", "1"), rate("carol", "dave", "0.5")];
        let out = lens(&atoms, "alice", &LensOptions::default());
        // carol: rated by bob (weight 0.8), voice 0.8 * 0.5.
        assert!(close(out["carol"].score, 1.0));
        assert!(close(out["carol"].confidence, 0.4));
        assert_eq!(out["carol"].hops, 2);
        // dave: carol's weight is 0.8 * 1 * 0.5 = 0.4, voice 0.2.
        assert!(close(out["dave"].score, 0.5));
        assert!(close(out["dave"].confidence, 0.2));
        assert_eq!(out["dave"].hops, 3);
    }

    #[test]
    fn depth_limits_the_cascade() {
        let atoms = [rate("alice", "bob", "1"), rate("bob", "carol", "1"), rate("carol", "dave", "1")];
        let one = lens(&atoms, "alice", &LensOptions { depth: 1, ..LensOptions::default() });
        assert_eq!(one.keys().collect::<Vec<_>>(), ["bob"]);
        let two = lens(&atoms, "alice", &LensOptions { depth: 2, ..LensOptions::default() });
        assert_eq!(two.keys().collect::<Vec<_>>(), ["bob", "carol"]);
        assert_eq!(lens(&atoms, "alice", &LensOptions { depth: 0, ..LensOptions::default() }).len(), 0);
    }

    #[test]
    fn distrust_is_visible_but_not_transitive() {
        let atoms = [rate("alice", "bob", "1"), rate("bob", "mallory", "-1"), rate("mallory", "scam", "1")];
        let out = lens(&atoms, "alice", &LensOptions::default());
        assert!(close(out["mallory"].score, -1.0));
        assert!(!out.contains_key("scam"));
    }

    #[test]
    fn own_rating_overrides_friends() {
        let atoms = [rate("alice", "bob", "1"), rate("bob", "carol", "1"), rate("alice", "carol", "-0.2")];
        let out = lens(&atoms, "alice", &LensOptions::default());
        assert!(close(out["carol"].score, -0.2));
        assert!(close(out["carol"].confidence, 1.0));
    }

    #[test]
    fn opinions_are_weighted_by_trust() {
        let atoms = [
            rate("alice", "bob", "1"),
            rate("alice", "carol", "0.25"),
            rate("bob", "cafe", "1"),
            rate("carol", "cafe", "-1"),
        ];
        let out = lens(&atoms, "alice", &LensOptions::default());
        // voices: bob 0.5, carol 0.125 → (0.5 - 0.125) / 0.625 = 0.6
        assert!(close(out["cafe"].score, 0.6));
        assert_eq!(out["cafe"].raters, 2);
        assert!(close(out["cafe"].confidence, 0.5));
    }

    #[test]
    fn strongest_path_wins_even_if_longer() {
        let atoms = [
            rate("alice", "weak", "0.1"),
            rate("weak", "target", "0.1"),
            rate("alice", "strong", "1"),
            rate("strong", "middle", "1"),
            rate("middle", "target", "1"),
            rate("target", "x", "1"),
        ];
        let out = lens(&atoms, "alice", &LensOptions { depth: 4, ..LensOptions::default() });
        // target's weight via weak: 0.1 * 0.1 * 0.5 = 0.005 (2 hops);
        // via strong → middle: 1 * (1 * 0.5) * (1 * 0.5) = 0.25 (3 hops).
        // So x is rated with voice 0.25 * 0.5.
        assert!(close(out["x"].confidence, 0.125));
        assert_eq!(out["x"].hops, 4);
    }

    #[test]
    fn topics_filter_the_whole_cascade() {
        let atoms = [
            about("alice", "bob", "1", "sushi"),
            about("bob", "sushi-bar", "0.9", "sushi"),
            about("alice", "carol", "1", "rust"),
            about("carol", "other-bar", "0.9", "sushi"),
        ];
        let out = lens(&atoms, "alice", &LensOptions { topic: Some("sushi".into()), ..LensOptions::default() });
        assert!(out.contains_key("sushi-bar"));
        assert!(!out.contains_key("other-bar"), "carol is trusted for rust, not sushi");
        assert!(!out.contains_key("carol"));
    }

    #[test]
    fn latest_rating_wins_and_contents_are_averaged() {
        let atoms = [
            rate("alice", "bob", "0.2").with_timestamp("2020-01-01T00:00:00Z".parse().unwrap()),
            rate("alice", "bob", "1").with_timestamp("2024-01-01T00:00:00Z".parse().unwrap()),
            rate("alice", "bob", "-1").with_timestamp("2010-01-01T00:00:00Z".parse().unwrap()),
            about("alice", "bob", "0", "chess"),
        ];
        let graph: TrustGraph = atoms.iter().collect();
        assert_eq!(graph.len(), 2);
        let out = lens(&atoms, "alice", &LensOptions::default());
        assert!(close(out["bob"].score, 0.5));
    }

    #[test]
    fn cycles_terminate_and_root_is_excluded() {
        let atoms = [
            rate("alice", "bob", "1"),
            rate("bob", "alice", "1"),
            rate("bob", "carol", "1"),
            rate("carol", "bob", "1"),
        ];
        let out = lens(&atoms, "alice", &LensOptions { depth: 10, ..LensOptions::default() });
        assert!(!out.contains_key("alice"));
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn atoms_without_values_are_ignored() {
        let graph: TrustGraph = [TrustAtom::new("alice", "bob")].iter().collect();
        assert_eq!(graph.len(), 0);
        assert_eq!(graph.lens("alice", &LensOptions::default()), []);
    }

    #[test]
    fn results_are_sorted_best_first() {
        let atoms = [rate("alice", "a", "0.1"), rate("alice", "b", "0.9"), rate("alice", "c", "-0.3")];
        let graph: TrustGraph = atoms.iter().collect();
        let order: Vec<_> = graph.lens("alice", &LensOptions::default()).into_iter().map(|e| e.target).collect();
        assert_eq!(order, ["b", "a", "c"]);
    }

    #[test]
    fn rollups_are_valid_atoms() {
        let atoms = [about("alice", "bob", "1", "sushi"), about("bob", "bar", "0.8", "sushi")];
        let graph: TrustGraph = atoms.iter().collect();
        let options = LensOptions { topic: Some("sushi".into()), ..LensOptions::default() };
        let entries = graph.lens("alice", &options);
        let rollups = TrustGraph::rollup("alice", &entries, &options, Timestamp::UNIX_EPOCH).unwrap();
        assert_eq!(rollups.len(), 2);
        for atom in &rollups {
            atom.validate().unwrap();
            assert_eq!(atom.source, "alice");
            assert_eq!(atom.content.as_deref(), Some("sushi"));
            assert_eq!(atom.extra["rollup"], "agent-lens");
        }
    }
}
