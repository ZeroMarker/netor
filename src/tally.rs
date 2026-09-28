//! Frequency counting shared by the `live` and `web` tables.

use std::collections::HashMap;

/// Sorts counts by descending frequency, breaking ties by key so that output
/// is stable across runs.
pub fn sorted_counts(values: &HashMap<String, u64>) -> Vec<(&str, u64)> {
    let mut rows = values
        .iter()
        .map(|(value, count)| (value.as_str(), *count))
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
        assert_eq!(sorted[0], ("c", 5));
        assert_eq!(sorted[1], ("a", 3));
        assert_eq!(sorted[2], ("b", 1));
    }

    #[test]
    fn breaks_ties_alphabetically() {
        let mut counts = HashMap::new();
        counts.insert("b".to_owned(), 2);
        counts.insert("a".to_owned(), 2);
        let sorted = sorted_counts(&counts);
        assert_eq!(sorted, vec![("a", 2), ("b", 2)]);
    }
}
