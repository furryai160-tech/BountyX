use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CvssScope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImpactMetric {
    None,
    Low,
    High,
}

/// Complete CVSS v3.1 Vector representation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cvss31Metrics {
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: CvssScope,
    pub confidentiality: ImpactMetric,
    pub integrity: ImpactMetric,
    pub availability: ImpactMetric,
}

impl Default for Cvss31Metrics {
    fn default() -> Self {
        Self {
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: CvssScope::Unchanged,
            confidentiality: ImpactMetric::Low,
            integrity: ImpactMetric::None,
            availability: ImpactMetric::None,
        }
    }
}

/// Official FIRST.org CVSS 3.1 Deterministic Calculation Engine in Rust
pub struct Cvss31Engine;

impl Cvss31Engine {
    /// Compute exact standard CVSS 3.1 Base Score and Severity
    pub fn calculate_base_score(metrics: &Cvss31Metrics) -> (f64, String, crate::security::risk::Severity) {
        let av = match metrics.attack_vector {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.20,
        };

        let ac = match metrics.attack_complexity {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        };

        let pr = match (metrics.scope, metrics.privileges_required) {
            (CvssScope::Unchanged, PrivilegesRequired::None) => 0.85,
            (CvssScope::Unchanged, PrivilegesRequired::Low) => 0.62,
            (CvssScope::Unchanged, PrivilegesRequired::High) => 0.27,
            (CvssScope::Changed, PrivilegesRequired::None) => 0.85,
            (CvssScope::Changed, PrivilegesRequired::Low) => 0.68,
            (CvssScope::Changed, PrivilegesRequired::High) => 0.50,
        };

        let ui = match metrics.user_interaction {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        };

        let c = match metrics.confidentiality {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        };

        let i = match metrics.integrity {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        };

        let a = match metrics.availability {
            ImpactMetric::None => 0.0,
            ImpactMetric::Low => 0.22,
            ImpactMetric::High => 0.56,
        };

        let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));

        let impact = match metrics.scope {
            CvssScope::Unchanged => 6.42 * iss,
            CvssScope::Changed => {
                7.52 * (iss - 0.029) - 3.25 * f64::max(iss - 0.02, 0.0).powf(15.0)
            }
        };

        let exploitability = 8.22 * av * ac * pr * ui;

        let raw_score = if impact <= 0.0 {
            0.0
        } else {
            match metrics.scope {
                CvssScope::Unchanged => f64::min(impact + exploitability, 10.0),
                CvssScope::Changed => f64::min(1.08 * (impact + exploitability), 10.0),
            }
        };

        // CVSS 3.1 standard round up to 1 decimal place: ceil(score * 10) / 10
        let base_score = Self::roundup(raw_score);

        let vector_str = format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            match metrics.attack_vector {
                AttackVector::Network => "N",
                AttackVector::Adjacent => "A",
                AttackVector::Local => "L",
                AttackVector::Physical => "P",
            },
            match metrics.attack_complexity {
                AttackComplexity::Low => "L",
                AttackComplexity::High => "H",
            },
            match metrics.privileges_required {
                PrivilegesRequired::None => "N",
                PrivilegesRequired::Low => "L",
                PrivilegesRequired::High => "H",
            },
            match metrics.user_interaction {
                UserInteraction::None => "N",
                UserInteraction::Required => "R",
            },
            match metrics.scope {
                CvssScope::Unchanged => "U",
                CvssScope::Changed => "C",
            },
            match metrics.confidentiality {
                ImpactMetric::None => "N",
                ImpactMetric::Low => "L",
                ImpactMetric::High => "H",
            },
            match metrics.integrity {
                ImpactMetric::None => "N",
                ImpactMetric::Low => "L",
                ImpactMetric::High => "H",
            },
            match metrics.availability {
                ImpactMetric::None => "N",
                ImpactMetric::Low => "L",
                ImpactMetric::High => "H",
            }
        );

        let severity = if base_score == 0.0 {
            crate::security::risk::Severity::Informational
        } else if base_score < 4.0 {
            crate::security::risk::Severity::Low
        } else if base_score < 7.0 {
            crate::security::risk::Severity::Medium
        } else if base_score < 9.0 {
            crate::security::risk::Severity::High
        } else {
            crate::security::risk::Severity::Critical
        };

        (base_score, vector_str, severity)
    }

    fn roundup(input: f64) -> f64 {
        let int_input = (input * 100000.0).round() as i64;
        if int_input % 10000 == 0 {
            int_input as f64 / 100000.0
        } else {
            ((int_input / 10000 + 1) as f64) / 10.0
        }
    }
}
