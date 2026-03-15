use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fireshark_core::Frame;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::blocks::Block;
use pcap_file::{DataLink, PcapError};

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
            let mut reader = PcapNgReader::new(file)?;
            validate_pcapng_linktypes(&mut reader)?;

            let mut file = reader.into_inner();
            file.seek(SeekFrom::Start(0))?;

            ReaderKind::PcapNg(PcapNgReader::new(file)?)
        } else if is_pcap_magic(magic) {
            let reader = PcapReader::new(file)?;
            validate_linktype(reader.header().datalink)?;
            ReaderKind::Pcap(reader)
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
                            .data(packet.data.into_owned())
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
                            .data(packet.data.into_owned())
                            .protocol("UNKNOWN")
                            .build()));
                    }
                    Ok(Block::SimplePacket(packet)) => {
                        return Some(Ok(Frame::builder()
                            .captured_len(packet.data.len())
                            .data(packet.data.into_owned())
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

fn validate_linktype(datalink: DataLink) -> Result<(), CaptureError> {
    if datalink == DataLink::ETHERNET {
        Ok(())
    } else {
        Err(CaptureError::UnsupportedLinkType { datalink })
    }
}

fn validate_pcapng_linktypes(reader: &mut PcapNgReader<File>) -> Result<(), CaptureError> {
    let mut interfaces = Vec::new();

    while let Some(block) = reader.next_block() {
        match block? {
            Block::SectionHeader(_) => interfaces.clear(),
            Block::InterfaceDescription(interface) => {
                validate_linktype(interface.linktype)?;
                interfaces.push(interface.linktype);
            }
            Block::EnhancedPacket(packet) => {
                let datalink = interfaces
                    .get(packet.interface_id as usize)
                    .copied()
                    .ok_or(PcapError::InvalidInterfaceId(packet.interface_id))?;
                validate_linktype(datalink)?;
            }
            Block::SimplePacket(_) => {
                let datalink = interfaces.first().copied().ok_or(PcapError::InvalidField(
                    "SimplePacketBlock: missing interface description",
                ))?;
                validate_linktype(datalink)?;
            }
            _ => {}
        }
    }

    Ok(())
}
