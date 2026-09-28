//! Command line surface for `netor`.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "netor",
    version,
    about = "System-level network traffic monitor"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub network: NetworkArgs,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Monitor live TCP connections from the operating system.
    Live(LiveArgs),

    /// Monitor website domains by parsing DNS and TLS SNI packets.
    Web(WebArgs),
}

#[derive(Debug, Args)]
pub struct NetworkArgs {
    /// Refresh interval in seconds.
    #[arg(short, long, default_value_t = 1.0, value_parser = positive_f64)]
    pub interval: f64,

    /// Only show interfaces whose name contains this text.
    #[arg(short = 'n', long)]
    pub interface: Option<String>,

    /// Include interfaces with no traffic in the current sample.
    #[arg(long)]
    pub all: bool,

    /// Print one sample and exit.
    #[arg(long)]
    pub once: bool,

    /// Output unit.
    #[arg(short, long, value_enum, default_value_t = Unit::Auto)]
    pub unit: Unit,
}

#[derive(Debug, Args)]
pub struct LiveArgs {
    /// Refresh interval in seconds.
    #[arg(short, long, default_value_t = 2.0, value_parser = positive_f64)]
    pub interval: f64,

    /// Print one snapshot and exit.
    #[arg(long)]
    pub once: bool,

    /// Number of remote endpoints to show.
    #[arg(long, default_value_t = 20, value_parser = positive_usize)]
    pub top: usize,

    /// Include non-established TCP states.
    #[arg(long)]
    pub all_states: bool,
}

#[derive(Debug, Args)]
pub struct WebArgs {
    /// Capture interval in seconds.
    #[arg(short, long, default_value_t = 5.0, value_parser = positive_f64)]
    pub interval: f64,

    /// Print one capture window and exit.
    #[arg(long)]
    pub once: bool,

    /// Number of domains to show.
    #[arg(long, default_value_t = 20, value_parser = positive_usize)]
    pub top: usize,

    /// Network interface name to bind, for example eth0. Linux only.
    #[arg(short = 'n', long)]
    pub interface: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Unit {
    Auto,
    Bytes,
    Bits,
}

/// Accepts only positive values that survive the conversion to `Duration`,
/// which would otherwise silently saturate to zero.
pub fn positive_f64(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| format!("`{value}` is not a number"))?;

    if parsed.is_finite()
        && parsed > 0.0
        && Duration::try_from_secs_f64(parsed).is_ok_and(|duration| !duration.is_zero())
    {
        Ok(parsed)
    } else {
        Err("value must be a positive, representable duration (at least 1 ns)".to_owned())
    }
}

pub fn positive_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("`{value}` is not a positive integer"))?;

    if parsed > 0 {
        Ok(parsed)
    } else {
        Err("value must be greater than 0".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_positive_intervals() {
        assert_eq!(positive_f64("0.5"), Ok(0.5));
        assert!(positive_f64("0").is_err());
        assert!(positive_f64("-1").is_err());
        assert!(positive_f64("nan").is_err());
    }

    #[test]
    fn rejects_unrepresentable_intervals() {
        for value in ["1e300", "1e-300", "0.0000000001"] {
            assert!(positive_f64(value).is_err(), "accepted {value}");
            assert!(Cli::try_parse_from(["netor", "--interval", value]).is_err());
        }
        assert_eq!(positive_f64("0.000000001"), Ok(1e-9));
    }

    #[test]
    fn validates_positive_f64_edge_cases() {
        assert!(positive_f64("inf").is_err());
        assert!(positive_f64("-inf").is_err());
        assert_eq!(positive_f64("1"), Ok(1.0));
        assert_eq!(positive_f64("0.001"), Ok(0.001));
    }

    #[test]
    fn validates_positive_top_limit() {
        assert_eq!(positive_usize("15"), Ok(15));
        assert!(positive_usize("0").is_err());
        assert!(positive_usize("abc").is_err());
    }

    #[test]
    fn rejects_non_positive_usize() {
        assert!(positive_usize("0").is_err());
        assert!(positive_usize("-5").is_err());
        assert_eq!(positive_usize("100"), Ok(100));
    }

    #[test]
    fn parses_subcommands() {
        assert!(matches!(
            Cli::try_parse_from(["netor", "live", "--once"]),
            Ok(Cli {
                command: Some(Command::Live(_)),
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from(["netor", "web", "--top", "5"]),
            Ok(Cli {
                command: Some(Command::Web(_)),
                ..
            })
        ));
    }
}
