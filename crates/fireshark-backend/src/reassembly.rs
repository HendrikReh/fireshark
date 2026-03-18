/// Stream reassembly types re-exported from `fireshark-tshark`.
///
/// These types are defined in the tshark crate (which produces them) and
/// re-exported here so consumers of the backend API have a single import path.
pub use fireshark_tshark::reassembly::{
    Direction, FollowMode, HttpExchange, StreamPayload, StreamSegment, TlsCertInfo,
};
