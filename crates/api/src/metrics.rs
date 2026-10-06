//! Prometheus counters in text exposition format, shared by both binaries.
//!
//! Label values are `&'static str` by construction, so a caller can never
//! inject cardinality: every label is one of the `reason()` strings the
//! rejection types already define.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

type Labels = Vec<(&'static str, &'static str)>;
/// (name, help, read-at-scrape).
type Gauge = (
    &'static str,
    &'static str,
    Box<dyn Fn() -> f64 + Send + Sync>,
);

#[derive(Default)]
pub struct Metrics {
    counters: Mutex<BTreeMap<(&'static str, Labels), u64>>,
    help: Mutex<BTreeMap<&'static str, &'static str>>,
    gauges: Mutex<Vec<Gauge>>,
    requests: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn describe(&self, name: &'static str, help: &'static str) {
        self.help
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name, help);
    }

    pub fn inc(&self, name: &'static str, labels: &[(&'static str, &'static str)]) {
        *self
            .counters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry((name, labels.to_vec()))
            .or_default() += 1;
    }

    /// A value read at scrape time (cache sizes, index size, ...).
    pub fn gauge(
        &self,
        name: &'static str,
        help: &'static str,
        read: impl Fn() -> f64 + Send + Sync + 'static,
    ) {
        self.gauges
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((name, help, Box::new(read)));
    }

    pub fn next_request_id(&self) -> u64 {
        self.requests.fetch_add(1, Ordering::Relaxed)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let help = self.help.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let counters = self
            .counters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut last = "";
        for ((name, labels), value) in &counters {
            if *name != last {
                if let Some(h) = help.get(name) {
                    let _ = writeln!(out, "# HELP {name} {h}");
                }
                let _ = writeln!(out, "# TYPE {name} counter");
                last = name;
            }
            let rendered: Vec<String> =
                labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
            if rendered.is_empty() {
                let _ = writeln!(out, "{name} {value}");
            } else {
                let _ = writeln!(out, "{name}{{{}}} {value}", rendered.join(","));
            }
        }
        for (name, h, read) in self.gauges.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            let _ = writeln!(
                out,
                "# HELP {name} {h}\n# TYPE {name} gauge\n{name} {}",
                read()
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_render_grouped_by_name() {
        let m = Metrics::new();
        m.describe("x_total", "things");
        m.inc("x_total", &[("door", "jwt"), ("outcome", "ok")]);
        m.inc("x_total", &[("door", "jwt"), ("outcome", "ok")]);
        m.inc("x_total", &[("door", "sigv4"), ("outcome", "expired")]);
        m.gauge("size", "entries", || 3.0);
        let text = m.render();
        assert_eq!(text.matches("# TYPE x_total counter").count(), 1);
        assert!(text.contains("x_total{door=\"jwt\",outcome=\"ok\"} 2"));
        assert!(text.contains("x_total{door=\"sigv4\",outcome=\"expired\"} 1"));
        assert!(text.contains("size 3"));
    }
}
