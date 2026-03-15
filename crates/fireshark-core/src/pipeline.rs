use crate::{Frame, Packet, PacketSummary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    frame: Frame,
    packet: Packet,
}

impl DecodedFrame {
    pub fn new(frame: Frame, packet: Packet) -> Self {
        Self { frame, packet }
    }

    pub fn frame(&self) -> &Frame {
        &self.frame
    }

    pub fn packet(&self) -> &Packet {
        &self.packet
    }

    pub fn summary(&self) -> PacketSummary {
        PacketSummary::from_packet(&self.packet, self.frame.captured_len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError<FrameError, DecodeError> {
    Frame(FrameError),
    Decode(DecodeError),
}

pub struct Pipeline<I, D> {
    frames: I,
    decoder: D,
}

impl<I, D> Pipeline<I, D> {
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
