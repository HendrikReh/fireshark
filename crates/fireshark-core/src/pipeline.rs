//! Decode pipeline that pairs frame sources with protocol decoders.

use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::stream::StreamTracker;
use crate::{Frame, Packet, PacketSummary};

/// A successfully decoded frame paired with its packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    frame: Frame,
    packet: Packet,
    stream_id: Option<u32>,
}

impl DecodedFrame {
    /// Wrap a frame and its decoded packet.
    pub fn new(frame: Frame, packet: Packet) -> Self {
        Self {
            frame,
            packet,
            stream_id: None,
        }
    }

    /// The original captured frame.
    pub fn frame(&self) -> &Frame {
        &self.frame
    }

    /// The decoded protocol layers.
    pub fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Stream ID assigned by a [`TrackingPipeline`], if available.
    pub fn stream_id(&self) -> Option<u32> {
        self.stream_id
    }

    /// Return a new frame with the given stream ID set.
    pub fn with_stream_id(mut self, id: Option<u32>) -> Self {
        self.stream_id = id;
        self
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

/// A [`Pipeline`] wrapper that assigns stream IDs via a [`StreamTracker`].
///
/// Each successfully decoded frame is passed through the tracker, which
/// extracts the 5-tuple and assigns (or looks up) a monotonic stream ID.
/// The ID is set on the [`DecodedFrame`] via [`DecodedFrame::with_stream_id`].
pub struct TrackingPipeline<I, D> {
    inner: Pipeline<I, D>,
    tracker: StreamTracker,
}

impl<I, D> TrackingPipeline<I, D> {
    /// Create a tracking pipeline from a frame iterator and decoder function.
    pub fn new(frames: I, decoder: D) -> Self {
        Self {
            inner: Pipeline::new(frames, decoder),
            tracker: StreamTracker::new(),
        }
    }

    /// Borrow the accumulated stream tracker.
    pub fn tracker(&self) -> &StreamTracker {
        &self.tracker
    }

    /// Consume the pipeline and return the stream tracker with all metadata.
    pub fn into_tracker(self) -> StreamTracker {
        self.tracker
    }
}

impl<I, D, FrameError, DecodeError> Iterator for TrackingPipeline<I, D>
where
    I: Iterator<Item = Result<Frame, FrameError>>,
    D: Fn(&[u8]) -> Result<Packet, DecodeError>,
{
    type Item = Result<DecodedFrame, PipelineError<FrameError, DecodeError>>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.inner.next()?;
        Some(result.map(|decoded| {
            let stream_id = self.tracker.assign(&decoded);
            decoded.with_stream_id(stream_id)
        }))
    }
}
