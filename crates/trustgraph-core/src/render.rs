//! Drawing an Agent Lens as a graph: Graphviz DOT or Mermaid.
//!
//! Both renderers draw the lens from the root's point of view: the root,
//! every agent along the strongest path to each rater, and every rated
//! target, with one edge per rating labelled with its value (and the topic,
//! if the lens has one). The root is drawn in bold (a stadium in Mermaid),
//! and targets show their lens score. Distrust (negative ratings) is drawn
//! dashed.
//!
//! The renderers use [`LensEntry::via`], so compute the lens with
//! [`LensOptions::explain`](crate::LensOptions::explain) set. Entries without
//! `via` are drawn as a single edge from the root, labelled with the score.
//!
//! This is pure string formatting: no I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, LensEntry};

/// A graph output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphFormat {
    /// Graphviz DOT (`dot -Tsvg`).
    Dot,
    /// A Mermaid flowchart (renders in GitHub Markdown).
    Mermaid,
}

impl FromStr for GraphFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "dot" => Ok(Self::Dot),
            "mermaid" => Ok(Self::Mermaid),
            _ => Err(Error::InvalidInput(format!("unknown graph format `{s}`; expected `dot` or `mermaid`"))),
        }
    }
}

/// How to label the drawing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RenderOptions {
    /// The lens topic, shown in the title and on every edge.
    pub topic: Option<String>,
    /// Display names for identifiers (e.g. contacts: DID → `bob`).
    /// Identifiers without a name are shortened with [`short_id`].
    pub labels: BTreeMap<String, String>,
}

impl RenderOptions {
    fn label(&self, id: &str) -> String {
        self.labels.get(id).cloned().unwrap_or_else(|| short_id(id))
    }
}

/// Shortens long `did:key` identifiers for display
/// (`did:key:z6MkhaXg…ta2doK`). Anything else is returned unchanged.
#[must_use]
pub fn short_id(id: &str) -> String {
    const HEAD: usize = "did:key:z6Mkxxxx".len();
    const TAIL: usize = 6;
    if id.starts_with("did:key:") && id.is_ascii() && id.len() > HEAD + TAIL + 4 {
        format!("{}…{}", &id[..HEAD], &id[id.len() - TAIL..])
    } else {
        id.to_owned()
    }
}

/// The nodes and edges to draw.
struct Picture<'a> {
    /// Node IDs, root first, then in order of first appearance.
    nodes: Vec<&'a str>,
    /// Lens score of each node that is a lens entry.
    scores: BTreeMap<&'a str, f64>,
    /// `(from, to) → rating`.
    edges: BTreeMap<(&'a str, &'a str), f64>,
}

impl<'a> Picture<'a> {
    fn new(root: &'a str, entries: &'a [LensEntry]) -> Self {
        let mut nodes = vec![root];
        let mut seen = BTreeSet::from([root]);
        let mut edges = BTreeMap::new();
        let mut add_node = |id: &'a str, nodes: &mut Vec<&'a str>| {
            if seen.insert(id) {
                nodes.push(id);
            }
        };
        for entry in entries {
            if let Some(via) = &entry.via {
                for hop in via.iter().flat_map(|v| &v.path) {
                    add_node(&hop.from, &mut nodes);
                    add_node(&hop.to, &mut nodes);
                    edges.insert((hop.from.as_str(), hop.to.as_str()), hop.value);
                }
            } else {
                edges.insert((root, entry.target.as_str()), entry.score);
            }
            add_node(&entry.target, &mut nodes);
        }
        let scores = entries.iter().map(|e| (e.target.as_str(), e.score)).collect();
        Self { nodes, scores, edges }
    }

    fn node_label(&self, id: &str, root: &str, options: &RenderOptions) -> String {
        let label = options.label(id);
        if id == root {
            label
        } else if let Some(score) = self.scores.get(id) {
            format!("{label}\nscore {score}")
        } else {
            label
        }
    }

    fn edge_label(value: f64, options: &RenderOptions) -> String {
        match &options.topic {
            Some(topic) => format!("{topic}: {value}"),
            None => value.to_string(),
        }
    }
}

fn title(root: &str, options: &RenderOptions) -> String {
    let mut title = format!("Trust lens of {}", options.label(root));
    if let Some(topic) = &options.topic {
        let _ = write!(title, " (topic: {topic})");
    }
    title
}

/// Draws `root`'s lens as Graphviz DOT.
#[must_use]
pub fn dot(root: &str, entries: &[LensEntry], options: &RenderOptions) -> String {
    fn quote(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    let picture = Picture::new(root, entries);
    let mut out = String::from("digraph lens {\n");
    let _ = writeln!(out, "  label={};", quote(&title(root, options)));
    out.push_str("  labelloc=t;\n  rankdir=LR;\n  node [shape=box, style=rounded];\n");
    for &id in &picture.nodes {
        let label = quote(&picture.node_label(id, root, options));
        if id == root {
            let _ = writeln!(out, "  {} [label={label}, style=\"rounded,bold\"];", quote(id));
        } else {
            let _ = writeln!(out, "  {} [label={label}];", quote(id));
        }
    }
    for (&(from, to), &value) in &picture.edges {
        let label = quote(&Picture::edge_label(value, options));
        let style = if value < 0.0 { ", style=dashed, color=red, fontcolor=red" } else { "" };
        let _ = writeln!(out, "  {} -> {} [label={label}{style}];", quote(from), quote(to));
    }
    out.push_str("}\n");
    out
}

/// Draws `root`'s lens as a Mermaid flowchart.
#[must_use]
pub fn mermaid(root: &str, entries: &[LensEntry], options: &RenderOptions) -> String {
    fn quote(s: &str) -> String {
        let escaped = s.replace('&', "#amp;").replace('"', "#quot;").replace('<', "#lt;").replace('>', "#gt;");
        format!("\"{}\"", escaped.replace('\n', "<br/>"))
    }

    let picture = Picture::new(root, entries);
    let ids: BTreeMap<&str, String> = picture.nodes.iter().enumerate().map(|(n, &id)| (id, format!("n{n}"))).collect();
    let mut out = String::new();
    let _ = writeln!(out, "---\ntitle: {}\n---", quote(&title(root, options)));
    out.push_str("flowchart LR\n");
    for &id in &picture.nodes {
        let label = quote(&picture.node_label(id, root, options));
        if id == root {
            let _ = writeln!(out, "  {}([{label}])", ids[id]);
        } else {
            let _ = writeln!(out, "  {}[{label}]", ids[id]);
        }
    }
    for (&(from, to), &value) in &picture.edges {
        let arrow = if value < 0.0 { "-.->" } else { "-->" };
        let label = quote(&Picture::edge_label(value, options));
        let _ = writeln!(out, "  {} {arrow}|{label}| {}", ids[from], ids[to]);
    }
    out
}

/// Draws `root`'s lens in `format`.
#[must_use]
pub fn graph(format: GraphFormat, root: &str, entries: &[LensEntry], options: &RenderOptions) -> String {
    match format {
        GraphFormat::Dot => dot(root, entries, options),
        GraphFormat::Mermaid => mermaid(root, entries, options),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LensOptions, TrustAtom, TrustGraph};

    fn entries(explain: bool) -> Vec<LensEntry> {
        let atoms = [
            TrustAtom::new("alice", "bob").with_value("1".parse().unwrap()),
            TrustAtom::new("bob", "https://sushi.example").with_value("0.8".parse().unwrap()),
            TrustAtom::new("bob", "say \"hi\"").with_value("-1".parse().unwrap()),
        ];
        let graph: TrustGraph = atoms.iter().collect();
        graph.lens("alice", &LensOptions { explain, ..LensOptions::default() })
    }

    #[test]
    fn dot_draws_the_lens() {
        let options = RenderOptions {
            topic: Some("sushi".into()),
            labels: BTreeMap::from([("bob".to_owned(), "Bob".to_owned())]),
        };
        let out = dot("alice", &entries(true), &options);
        assert!(out.starts_with("digraph lens {\n"), "{out}");
        assert!(out.ends_with("}\n"));
        assert!(out.contains("label=\"Trust lens of alice (topic: sushi)\""), "{out}");
        assert!(out.contains("\"alice\" [label=\"alice\", style=\"rounded,bold\"];"), "{out}");
        assert!(out.contains("\"bob\" [label=\"Bob\\nscore 1\"];"), "{out}");
        assert!(out.contains("\"alice\" -> \"bob\" [label=\"sushi: 1\"];"), "{out}");
        assert!(out.contains("\"bob\" -> \"https://sushi.example\" [label=\"sushi: 0.8\"];"), "{out}");
        assert!(out.contains("\"bob\" -> \"say \\\"hi\\\"\" [label=\"sushi: -1\", style=dashed"), "{out}");
    }

    #[test]
    fn mermaid_draws_the_lens() {
        let out = mermaid("alice", &entries(true), &RenderOptions::default());
        assert!(out.starts_with("---\ntitle: \"Trust lens of alice\"\n---\nflowchart LR\n"), "{out}");
        assert!(out.contains("  n0([\"alice\"])\n"), "{out}");
        assert!(out.contains("  n1[\"bob<br/>score 1\"]\n"), "{out}");
        assert!(out.contains("  n0 -->|\"1\"| n1\n"), "{out}");
        assert!(out.contains("#quot;hi#quot;"), "quotes are escaped: {out}");
        assert!(out.contains("-.->|\"-1\"|"), "distrust is dotted: {out}");
    }

    #[test]
    fn without_explanations_edges_come_from_the_root() {
        let out = dot("alice", &entries(false), &RenderOptions::default());
        assert!(out.contains("\"alice\" -> \"https://sushi.example\" [label=\"0.8\"];"), "{out}");
        assert_eq!(graph(GraphFormat::Dot, "alice", &entries(false), &RenderOptions::default()), out);
    }

    #[test]
    fn empty_lens_is_just_the_root() {
        let out = mermaid("alice", &[], &RenderOptions::default());
        assert_eq!(out.lines().filter(|l| l.contains("-->")).count(), 0);
        assert!(out.contains("n0([\"alice\"])"));
    }

    #[test]
    fn formats_and_ids() {
        assert_eq!("dot".parse::<GraphFormat>().unwrap(), GraphFormat::Dot);
        assert_eq!("mermaid".parse::<GraphFormat>().unwrap(), GraphFormat::Mermaid);
        assert!("svg".parse::<GraphFormat>().is_err());
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        assert_eq!(short_id(did), "did:key:z6MkhaXg…ta2doK");
        assert_eq!(short_id("https://sushi.example"), "https://sushi.example");
        assert_eq!(short_id("did:key:z6Mk"), "did:key:z6Mk");
    }
}
