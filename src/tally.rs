//! Frequency counting shared by the `live` and `web` tables.
//!
//! Callers count by borrowed keys so that no `String` is allocated per
//! captured packet; formatting happens only for the rows that are printed.

use std::collections::HashMap;

/// Sorts counts by descending frequency, breaking ties by key so that output
/// is stable across runs.
pub fn sorted_counts<K: Ord>(values: &HashMap<K, u64>) -> Vec<(&K, u64)> {
    let mut rows = values
        .iter()
        .map(|(key, count)| (key, *count))
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_counts_by_frequency() {
        let mut counts = HashMap::new();
        counts.insert("a".to_owned(), 3);
        counts.insert("b".to_owned(), 1);
        counts.insert("c".to_owned(), 5);
        let sorted = sorted_counts(&counts);
        assert_eq!(sorted[0], (&"c".to_owned(), 5));
        assert_eq!(sorted[1], (&"a".to_owned(), 3));
        assert_eq!(sorted[2], (&"b".to_owned(), 1));
    }

    #[test]
    fn breaks_ties_alphabetically() {
        let mut counts = HashMap::new();
        counts.insert("b".to_owned(), 2);
        counts.insert("a".to_owned(), 2);
        let sorted = sorted_counts(&counts);
        assert_eq!(sorted, vec![(&"a".to_owned(), 2), (&"b".to_owned(), 2)]);
    }

    #[test]
    fn counts_borrowed_keys_without_allocating() {
        let domains = ["example.com", "example.com", "other.com"];
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for domain in &domains {
            *counts.entry(*domain).or_default() += 1;
        }

        let sorted = sorted_counts(&counts);
        assert_eq!(sorted[0], (&"example.com", 2));
        assert_eq!(sorted[1], (&"other.com", 1));
    }
}
