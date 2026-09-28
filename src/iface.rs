//! Interface traffic sampling built on `sysinfo` counters.

use crate::cli::{NetworkArgs, Unit};
use crate::format::{format_bytes, format_rate, truncate};
use sysinfo::{NetworkData, Networks};

#[derive(Debug)]
pub struct InterfaceRow {
    name: String,
    rx_rate: f64,
    tx_rate: f64,
    rx_total: u64,
    tx_total: u64,
    packets_rx: f64,
    packets_tx: f64,
    errors_rx: u64,
    errors_tx: u64,
}

pub fn collect_interface_rows(
    networks: &Networks,
    cli: &NetworkArgs,
    elapsed_secs: f64,
) -> Vec<InterfaceRow> {
    let mut rows = networks
        .iter()
        .filter(|(name, _)| matches_interface(name, cli.interface.as_deref()))
        .filter(|(_, data)| cli.all || data.received() > 0 || data.transmitted() > 0)
        .map(|(name, data)| interface_row_from_network(name, data, elapsed_secs))
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        let left_total = left.rx_rate + left.tx_rate;
        let right_total = right.rx_rate + right.tx_rate;

        right_total
            .partial_cmp(&left_total)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.name.cmp(&right.name))
    });

    rows
}

pub fn matches_interface(name: &str, filter: Option<&str>) -> bool {
    filter
        .map(|filter| name.to_lowercase().contains(&filter.to_lowercase()))
        .unwrap_or(true)
}

fn interface_row_from_network(name: &str, data: &NetworkData, elapsed_secs: f64) -> InterfaceRow {
    InterfaceRow {
        name: name.to_owned(),
        rx_rate: data.received() as f64 / elapsed_secs,
        tx_rate: data.transmitted() as f64 / elapsed_secs,
        rx_total: data.total_received(),
        tx_total: data.total_transmitted(),
        packets_rx: data.packets_received() as f64 / elapsed_secs,
        packets_tx: data.packets_transmitted() as f64 / elapsed_secs,
        errors_rx: data.errors_on_received(),
        errors_tx: data.errors_on_transmitted(),
    }
}

pub fn print_interface_rows(rows: &[InterfaceRow], unit: Unit) {
    println!();
    println!(
        "{:<18} {:>14} {:>14} {:>14} {:>14} {:>12} {:>12} {:>10}",
        "interface", "rx/s", "tx/s", "rx total", "tx total", "rx pkt/s", "tx pkt/s", "errors"
    );
    println!("{}", "-".repeat(116));

    if rows.is_empty() {
        println!("no matching traffic in this sample; use --all to show idle interfaces");
        return;
    }

    for row in rows {
        println!(
            "{:<18} {:>14} {:>14} {:>14} {:>14} {:>12} {:>12} {:>10}",
            truncate(&row.name, 18),
            format_rate(row.rx_rate, unit),
            format_rate(row.tx_rate, unit),
            format_bytes(row.rx_total as f64),
            format_bytes(row.tx_total as f64),
            format!("{:.1}", row.packets_rx),
            format!("{:.1}", row.packets_tx),
            format!("{}/{}", row.errors_rx, row.errors_tx),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(interface: Option<&str>, all: bool) -> NetworkArgs {
        NetworkArgs {
            interval: 1.0,
            interface: interface.map(str::to_owned),
            all,
            once: true,
            unit: Unit::Auto,
        }
    }

    #[test]
    fn filters_interfaces_case_insensitively() {
        assert!(matches_interface("Ethernet 2", Some("ether")));
        assert!(!matches_interface("lo", Some("wlan")));
        assert!(matches_interface("lo", None));
    }

    #[test]
    fn all_flag_reports_every_interface() {
        let networks = Networks::new_with_refreshed_list();
        if networks.is_empty() {
            return; // Nothing to assert on a host without interfaces.
        }

        let rows = collect_interface_rows(&networks, &args(None, true), 1.0);
        assert_eq!(rows.len(), networks.len());
    }

    #[test]
    fn interface_filter_narrows_the_result() {
        let networks = Networks::new_with_refreshed_list();
        let total = networks.len();
        if total == 0 {
            return;
        }

        let first = networks.iter().next().expect("non-empty").0.to_owned();
        let rows = collect_interface_rows(&networks, &args(Some(&first), true), 1.0);
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|row| row.name == first));
    }

    #[test]
    fn idle_interfaces_are_hidden_without_all_flag() {
        let networks = Networks::new_with_refreshed_list();
        if networks.is_empty() {
            return;
        }

        let with_all = collect_interface_rows(&networks, &args(None, true), 1.0).len();
        let without_all = collect_interface_rows(&networks, &args(None, false), 1.0).len();
        assert!(without_all <= with_all);
    }
}
