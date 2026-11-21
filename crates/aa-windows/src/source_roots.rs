//! Caller-declared distribution roots are logical input identifiers, never host paths.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceRoot {
    /// Logical artifact path of the INF inside the supplied tree.
    pub inf: String,
    /// Logical directory/container path, or `.` for the outer input namespace.
    pub root: String,
}

/// Validate before publication or use, including callers that bypass the command line.
pub fn validate(roots: &[SourceRoot]) -> Result<Vec<SourceRoot>, &'static str> {
    if roots.len() > 32 {
        return Err("at most 32 Windows source-root assignments are supported");
    }
    let valid = |path: &str| {
        !path.is_empty()
            && path.len() <= 8192
            && path.split('/').count() <= 512
            && path.split('/').all(crate::references::ordinary_component)
    };
    let mut normalized = Vec::new();
    for assignment in roots {
        if !valid(&assignment.inf)
            || !assignment.inf.to_ascii_lowercase().ends_with(".inf")
            || (assignment.root != "." && !valid(&assignment.root))
        {
            return Err(
                "Windows source roots require ASCII logical INF/root paths; host paths, escapes, aliases and variables are unsupported",
            );
        }
        normalized.push(SourceRoot { inf: assignment.inf.to_ascii_lowercase(), root: assignment.root.to_ascii_lowercase() });
    }
    normalized.sort();
    normalized.dedup();
    if normalized.windows(2).any(|pair| pair[0].inf == pair[1].inf) {
        return Err("one logical INF cannot have conflicting distribution roots");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logical_assignments_are_bounded_canonical_and_cannot_name_host_paths() {
        let roots = vec![
            SourceRoot { inf: "Pkg/DRIVER.inf".into(), root: "PKG".into() },
            SourceRoot { inf: "pkg/driver.inf".into(), root: "pkg".into() },
        ];
        let normalized = validate(&roots).expect("equivalent assignments");
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].root, "pkg");
        for root in ["C:/private", "\\\\server\\share", "../outside", "a/../b", "CON", "%Root%", "", "a//b", "nonascii-\u{212a}"] {
            assert!(validate(&[SourceRoot { inf: "a.inf".into(), root: root.into() }]).is_err(), "{root}");
        }
        assert!(
            validate(&[SourceRoot { inf: "a.inf".into(), root: ".".into() }, SourceRoot { inf: "A.INF".into(), root: "pkg".into() }])
                .is_err()
        );
        assert!(validate(&vec![SourceRoot { inf: "a.inf".into(), root: ".".into() }; 33]).is_err());
    }
}
