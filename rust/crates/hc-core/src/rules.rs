//! Rule-based dictionary mutations, mirroring `src/hash_cracker/rules.py`:
//! deterministic per-word variant lists, original word first, budget-truncated
//! expansion.

/// Preset registry order and labels (UI selects + CLI choices).
pub const RULE_PRESET_LABELS: &[(&str, &str)] = &[
    ("none", "No rules (original words only)"),
    ("capitalize", "Capitalize first letter"),
    ("upper", "UPPERCASE"),
    ("lower", "lowercase"),
    ("leetspeak", "Leetspeak (a→4, e→3, i→1, o→0, s→5)"),
    ("append_digits_0_99", "Append digits 0-99"),
    ("append_years", "Append years 1990-2029"),
    ("all", "All of the above combined"),
];

/// Error for unknown preset names (message mirrors Python).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError(pub String);

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RuleError {}

/// `word.capitalize()`: first character uppercased, the rest lowercased.
fn py_capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => {
            let mut out: String = first.to_uppercase().collect();
            out.extend(chars.flat_map(|c| c.to_lowercase()));
            out
        }
    }
}

fn variants_capitalize(word: &str) -> Vec<String> {
    let variant = py_capitalize(word);
    if variant != word {
        vec![variant]
    } else {
        Vec::new()
    }
}

fn variants_upper(word: &str) -> Vec<String> {
    let variant = word.to_uppercase();
    if variant != word {
        vec![variant]
    } else {
        Vec::new()
    }
}

fn variants_lower(word: &str) -> Vec<String> {
    let variant = word.to_lowercase();
    if variant != word {
        vec![variant]
    } else {
        Vec::new()
    }
}

fn variants_leetspeak(word: &str) -> Vec<String> {
    let variant: String = word
        .chars()
        .map(|c| match c {
            'a' => '4',
            'e' => '3',
            'i' => '1',
            'o' => '0',
            's' => '5',
            other => other,
        })
        .collect();
    if variant != word {
        vec![variant]
    } else {
        Vec::new()
    }
}

fn variants_append_digits(word: &str) -> Vec<String> {
    (0u32..=99).map(|n| format!("{word}{n}")).collect()
}

fn variants_append_years(word: &str) -> Vec<String> {
    (1990u32..=2029).map(|y| format!("{word}{y}")).collect()
}

/// `all`: deduplicated union of every preset's variants in registry order.
fn variants_all(word: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for variants in [
        variants_capitalize(word),
        variants_upper(word),
        variants_lower(word),
        variants_leetspeak(word),
        variants_append_digits(word),
        variants_append_years(word),
    ]
    .into_iter()
    {
        for variant in variants {
            if !seen.contains(&variant) {
                seen.push(variant);
            }
        }
    }
    seen
}

/// A rule preset's per-word variant function.
pub type VariantFn = fn(&str) -> Vec<String>;

/// Resolve a preset name to its variant function; `none` resolves to `None`.
pub fn resolve_rules_preset(name: &str) -> Result<Option<VariantFn>, RuleError> {
    match name {
        "none" => Ok(None),
        "capitalize" => Ok(Some(variants_capitalize)),
        "upper" => Ok(Some(variants_upper)),
        "lower" => Ok(Some(variants_lower)),
        "leetspeak" => Ok(Some(variants_leetspeak)),
        "append_digits_0_99" => Ok(Some(variants_append_digits)),
        "append_years" => Ok(Some(variants_append_years)),
        "all" => Ok(Some(variants_all)),
        other => {
            let mut known: Vec<&str> = RULE_PRESET_LABELS.iter().map(|(n, _)| *n).collect();
            known.retain(|n| *n != "none");
            known.sort_unstable();
            Err(RuleError(format!(
                "Unknown rules preset '{other}'. Known presets: {}.",
                known.join(", ")
            )))
        }
    }
}

/// Rule-expanded batch stream, truncated exactly at the candidate budget.
/// Each incoming batch is expanded independently (original word first, then
/// its variants).
pub struct RuleExpander {
    variants_for: Option<fn(&str) -> Vec<String>>,
    budget: u64,
    emitted: u64,
}

impl RuleExpander {
    pub fn new(variants_for: Option<fn(&str) -> Vec<String>>, budget: u64) -> Self {
        Self {
            variants_for,
            budget,
            emitted: 0,
        }
    }

    /// Expand one incoming batch; `None` when the budget is exhausted.
    pub fn expand_batch(&mut self, batch: &[String]) -> Option<Vec<String>> {
        if self.emitted >= self.budget {
            return None;
        }
        let mut expanded = Vec::new();
        for word in batch {
            expanded.push(word.clone());
            self.emitted += 1;
            if self.emitted >= self.budget {
                return Some(std::mem::take(&mut expanded));
            }
            if let Some(variants_for) = self.variants_for {
                for variant in variants_for(word) {
                    expanded.push(variant);
                    self.emitted += 1;
                    if self.emitted >= self.budget {
                        return Some(std::mem::take(&mut expanded));
                    }
                }
            }
        }
        if expanded.is_empty() {
            None
        } else {
            Some(expanded)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capitalize_variants_skip_unchanged() {
        assert_eq!(variants_capitalize("hash"), vec!["Hash"]);
        assert!(variants_capitalize("Hash").is_empty());
        // Python capitalize() lowercases the rest.
        assert_eq!(variants_capitalize("hASH"), vec!["Hash"]);
    }

    #[test]
    fn leetspeak_map_is_pinned() {
        assert_eq!(variants_leetspeak("passwords"), vec!["p455w0rd5"]);
        assert!(variants_leetspeak("12345").is_empty());
    }

    #[test]
    fn append_variants_ranges() {
        assert_eq!(variants_append_digits("ab").len(), 100);
        assert_eq!(variants_append_digits("ab")[0], "ab0");
        assert_eq!(variants_append_digits("ab")[99], "ab99");
        assert_eq!(variants_append_years("ab")[0], "ab1990");
        assert_eq!(variants_append_years("ab").last().unwrap(), "ab2029");
    }

    #[test]
    fn all_union_is_deduped_in_registry_order() {
        let v = variants_all("HASH");
        // capitalize("HASH") == "Hash" (changed), upper unchanged, lower == "hash",
        // leet unchanged ("HASH" has no lowercase leet targets), digits, years.
        assert_eq!(v[0], "Hash");
        assert!(v.contains(&"hash".to_string()));
        assert_eq!(v.iter().position(|x| x == "hash"), Some(1));
        assert!(v.contains(&"HASH0".to_string()));
        assert_eq!(v.len(), 1 + 1 + 100 + 40);
    }

    #[test]
    fn unknown_preset_message_lists_known() {
        let err = resolve_rules_preset("bogus").unwrap_err();
        assert_eq!(
            err.0,
            "Unknown rules preset 'bogus'. Known presets: all, append_digits_0_99, \
             append_years, capitalize, leetspeak, lower, upper."
        );
    }

    #[test]
    fn expansion_truncates_exactly_at_budget() {
        let mut exp = RuleExpander::new(Some(variants_append_digits), 10);
        let out = exp
            .expand_batch(&["ab".to_string(), "cd".to_string()])
            .unwrap();
        // original "ab", then digit variants truncated at the budget
        assert_eq!(out.len(), 10);
        assert_eq!(out[0], "ab");
        assert_eq!(out[9], "ab8");
        // Budget exhausted: nothing more.
        assert!(exp.expand_batch(&["cd".to_string()]).is_none());
    }

    #[test]
    fn expansion_without_rules_emits_originals_only() {
        let mut exp = RuleExpander::new(None, 1_000);
        let out = exp
            .expand_batch(&["a".to_string(), "b".to_string()])
            .unwrap();
        assert_eq!(out, vec!["a", "b"]);
    }
}
