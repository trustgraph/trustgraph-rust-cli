//! Plain-text tables for `--format table`: aligned columns, for people.
//! Scripts should use the default JSON output instead.

use std::collections::BTreeMap;

use trustgraph_core::render::short_id;

/// Lays out `rows` under `headers`, columns separated by two spaces. Returns
/// one string per line, header first, without trailing spaces.
pub fn layout(headers: &[&str], rows: &[Vec<String>]) -> Vec<String> {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let header: Vec<String> = headers.iter().map(|h| (*h).to_owned()).collect();
    std::iter::once(&header)
        .chain(rows)
        .map(|row| {
            let mut line = String::new();
            for (n, (cell, width)) in row.iter().zip(&widths).enumerate() {
                if n > 0 {
                    line.push_str("  ");
                }
                line.push_str(cell);
                line.extend(std::iter::repeat_n(' ', width - cell.chars().count()));
            }
            line.trim_end().to_owned()
        })
        .collect()
}

/// How to show an identifier: its contact name, or a shortened DID.
pub fn name(id: &str, labels: &BTreeMap<String, String>) -> String {
    labels.get(id).cloned().unwrap_or_else(|| short_id(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_line_up() {
        let rows = vec![vec!["a".to_owned(), "1".to_owned()], vec!["longer".to_owned(), String::new()]];
        assert_eq!(layout(&["NAME", "N"], &rows), ["NAME    N", "a       1", "longer"]);
        assert_eq!(layout(&["X"], &[]), ["X"]);
    }

    #[test]
    fn names_prefer_contacts() {
        let labels = BTreeMap::from([("did:key:z6MkBob".to_owned(), "@bob".to_owned())]);
        assert_eq!(name("did:key:z6MkBob", &labels), "@bob");
        assert_eq!(name("https://x.example", &labels), "https://x.example");
    }
}
