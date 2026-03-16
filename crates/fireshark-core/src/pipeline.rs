//! Decode pipeline that pairs frame sources with protocol decoders.

use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::{Frame, Packet, PacketSummary};

/// A successfully decoded frame paired with its packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    frame: Frame,
    packet: Packet,
}

impl DecodedFrame {
    /// Wrap a frame and its decoded packet.
    pub fn new(frame: Frame, packet: Packet) -> Self {
        Self { frame, packet }
    }

    /// The original captured frame.
    pub fn frame(&self) -> &Frame {
        &self.frame
    }

    /// The decoded protocol layers.
    pub fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Build a human-readable summary.
    pub fn summary(&self) -> PacketSummary {
        PacketSummary::from_packet(&self.packet, &self.frame)
    }
}

/// Error from either the frame source or the decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError<FrameError, DecodeError> {
    /// The frame source produced an error.
    Frame(FrameError),
    /// The decoder produced an error.
    Decode(DecodeError),
}

impl<FrameError, DecodeError> Display for PipelineError<FrameError, DecodeError>
where
    FrameError: Display,
    DecodeError: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "frame error: {error}"),
            Self::Decode(error) => write!(f, "decode error: {error}"),
        }
    }
}

impl<FrameError, DecodeError> Error for PipelineError<FrameError, DecodeError>
where
    FrameError: Error + 'static,
    DecodeError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::Decode(error) => Some(error),
        }
    }
}

/// An iterator that reads frames and decodes each one into a [`DecodedFrame`].
pub struct Pipeline<I, D> {
    frames: I,
    decoder: D,
}

impl<I, D> Pipeline<I, D> {
    /// Create a pipeline from a frame iterator and a decoder function.
    pub fn new(frames: I, decoder: D) -> Self {
        Self { frames, decoder }
    }
}

impl<I, D, FrameError, DecodeError> Iterator for Pipeline<I, D>
where
    I: Iterator<Item = Result<Frame, FrameError>>,
    D: Fn(&[u8]) -> Result<Packet, DecodeError>,
{
    type Item = Result<DecodedFrame, PipelineError<FrameError, DecodeError>>;

    fn next(&mut self) -> Option<Self::Item> {
        let frame = match self.frames.next()? {
            Ok(frame) => frame,
            Err(error) => return Some(Err(PipelineError::Frame(error))),
        };

        let packet = match (self.decoder)(frame.data()) {
            Ok(packet) => packet,
            Err(error) => return Some(Err(PipelineError::Decode(error))),
        };

        Some(Ok(DecodedFrame::new(frame, packet)))
    }
}
