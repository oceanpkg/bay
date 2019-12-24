fn main() {
    match version_check::is_feature_flaggable() {
        Some(true) => cargo_emit::rustc_cfg!("has_features"),
        Some(false) => {},
        None => cargo_emit::warning!("Could not determine `rustc` version"),
    }
}
