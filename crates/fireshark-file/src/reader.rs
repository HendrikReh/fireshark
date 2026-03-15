use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fireshark_core::Frame;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::blocks::Block;

use crate::CaptureError;

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

pub struct CaptureReader {
    inner: ReaderKind,
}

enum ReaderKind {
    Pcap(PcapReader<File>),
    PcapNg(PcapNgReader<File>),
}

impl CaptureReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CaptureError> {
        let mut file = File::open(path)?;
        let mut magic = [0_u8; 4];
        file.read_exact(&mut magic)?;
        file.seek(SeekFrom::Start(0))?;

        let inner = if magic == PCAPNG_MAGIC {
            ReaderKind::PcapNg(PcapNgReader::new(file)?)
        } else if is_pcap_magic(magic) {
            ReaderKind::Pcap(PcapReader::new(file)?)
        } else {
            return Err(CaptureError::UnsupportedFormat);
        };

        Ok(Self { inner })
    }
}

impl Iterator for CaptureReader {
    type Item = Result<Frame, CaptureError>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            ReaderKind::Pcap(reader) => reader.next_packet().map(|packet| {
                packet
                    .map(|packet| {
                        Frame::builder()
                            .captured_len(packet.data.len())
                            .protocol("UNKNOWN")
                            .build()
                    })
                    .map_err(CaptureError::from)
            }),
            ReaderKind::PcapNg(reader) => loop {
                let next_block = reader.next_block()?;
                match next_block {
                    Ok(Block::EnhancedPacket(packet)) => {
                        return Some(Ok(Frame::builder()
                            .captured_len(packet.data.len())
                            .protocol("UNKNOWN")
                            .build()));
                    }
                    Ok(Block::SimplePacket(packet)) => {
                        return Some(Ok(Frame::builder()
                            .captured_len(packet.data.len())
                            .protocol("UNKNOWN")
                            .build()));
                    }
                    Ok(_) => continue,
                    Err(error) => return Some(Err(CaptureError::from(error))),
                }
            },
        }
    }
}

fn is_pcap_magic(magic: [u8; 4]) -> bool {
    matches!(
        magic,
        [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d]
    )
}
