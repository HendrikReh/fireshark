pub fn matches_filter(value: &str, filter: Option<&str>) -> bool {
    match filter {
        Some(filter) => value.eq_ignore_ascii_case(filter),
        None => true,
    }
}
