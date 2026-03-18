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
