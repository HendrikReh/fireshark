pub mod ast;
mod error;
mod evaluate;
mod fields;
pub(crate) mod lexer;
mod parser;

pub use error::FilterError;
pub use evaluate::evaluate;
pub use parser::parse;

#[derive(Debug, Clone)]
pub struct CompiledFilter(ast::Expr);

pub fn compile(input: &str) -> Result<CompiledFilter, FilterError> {
    parse(input).map(CompiledFilter)
}

pub fn matches(filter: &CompiledFilter, decoded: &fireshark_core::DecodedFrame) -> bool {
    evaluate(&filter.0, decoded)
}

/// Return any unrecognized field names in the filter expression.
///
/// Useful for warning users about potential typos. Returns an empty vec
/// if all field names are known.
pub fn unknown_field_names(filter: &CompiledFilter) -> Vec<String> {
    let mut unknown = Vec::new();
    collect_field_names(&filter.0, &mut unknown);
    unknown
}

fn collect_field_names(expr: &ast::Expr, unknown: &mut Vec<String>) {
    match expr {
        ast::Expr::And(l, r) | ast::Expr::Or(l, r) => {
            collect_field_names(l, unknown);
            collect_field_names(r, unknown);
        }
        ast::Expr::Not(e) => collect_field_names(e, unknown),
        ast::Expr::Compare(field, _, _) | ast::Expr::BareField(field) => {
            if !fields::KNOWN_FIELDS.contains(&field.as_str()) {
                unknown.push(field.clone());
            }
        }
        ast::Expr::HasProtocol(_) | ast::Expr::Shorthand(_) => {}
    }
}
