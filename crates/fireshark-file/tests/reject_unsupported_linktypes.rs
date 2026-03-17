use std::borrow::Cow;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fireshark_file::{CaptureError, CaptureReader};
use pcap_file::DataLink;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::blocks::section_header::SectionHeaderBlock;
use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};

#[test]
fn rejects_non_ethernet_pcap() {
    let path = temp_capture_path("raw", "pcap");
    write_raw_pcap(&path);

    let result = CaptureReader::open(&path);

    fs::remove_file(&path).unwrap();
    assert!(matches!(
        result,
        Err(CaptureError::UnsupportedLinkType {
            datalink: DataLink::RAW
        })
    ));
}

#[test]
fn rejects_non_ethernet_pcapng() {
    let path = temp_capture_path("raw", "pcapng");
    write_raw_pcapng(&path);

    let result = CaptureReader::open(&path);

    fs::remove_file(&path).unwrap();
    assert!(matches!(
        result,
        Err(CaptureError::UnsupportedLinkType {
            datalink: DataLink::RAW
        })
    ));
}

fn temp_capture_path(prefix: &str, extension: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "fireshark-{prefix}-{unique}-{}.{}",
        std::process::id(),
        extension
    ))
}

fn write_raw_pcap(path: &PathBuf) {
    let file = fs::File::create(path).unwrap();
    let header = PcapHeader {
        datalink: DataLink::RAW,
        ..PcapHeader::default()
    };
    let mut writer = PcapWriter::with_header(file, header).unwrap();
    let packet = PcapPacket::new(Duration::ZERO, 20, &[0_u8; 20]);
    writer.write_packet(&packet).unwrap();
    writer.flush().unwrap();
}

fn write_raw_pcapng(path: &PathBuf) {
    let file = fs::File::create(path).unwrap();
    let mut writer = PcapNgWriter::new(file).unwrap();
    let interface = InterfaceDescriptionBlock::new(DataLink::RAW, 0xffff);
    writer.write_pcapng_block(interface).unwrap();

    let mut packet = EnhancedPacketBlock::default();
    packet.interface_id = 0;
    packet.timestamp = Duration::ZERO;
    packet.original_len = 20;
    packet.data = Cow::Borrowed(&[0_u8; 20]);
    writer.write_pcapng_block(packet).unwrap();
}

#[test]
fn rejects_pcapng_with_non_ethernet_in_later_section() {
    let path = temp_capture_path("multi-section", "pcapng");
    write_multi_section_pcapng(&path);

    let result = CaptureReader::open(&path);

    fs::remove_file(&path).unwrap();
    assert!(matches!(
        result,
        Err(CaptureError::UnsupportedLinkType {
            datalink: DataLink::RAW
        })
    ));
}

/// Write a multi-section pcapng where section 1 has Ethernet (valid) and
/// section 2 has RAW (invalid). Validation must scan past the first packet
/// to catch the second section's non-Ethernet interface.
fn write_multi_section_pcapng(path: &PathBuf) {
    let file = fs::File::create(path).unwrap();
    let mut writer = PcapNgWriter::new(file).unwrap();

    // Section 1: Ethernet interface + one packet
    let iface_eth = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 0xffff);
    writer.write_pcapng_block(iface_eth).unwrap();

    let mut packet = EnhancedPacketBlock::default();
    packet.interface_id = 0;
    packet.timestamp = Duration::ZERO;
    packet.original_len = 20;
    packet.data = Cow::Borrowed(&[0_u8; 20]);
    writer.write_pcapng_block(packet).unwrap();

    // Section 2: new SHB resets interfaces, then RAW interface + packet
    let shb = SectionHeaderBlock::default();
    writer.write_block(&shb.into_block()).unwrap();

    let iface_raw = InterfaceDescriptionBlock::new(DataLink::RAW, 0xffff);
    writer.write_pcapng_block(iface_raw).unwrap();

    let mut packet2 = EnhancedPacketBlock::default();
    packet2.interface_id = 0;
    packet2.timestamp = Duration::ZERO;
    packet2.original_len = 20;
    packet2.data = Cow::Borrowed(&[0_u8; 20]);
    writer.write_pcapng_block(packet2).unwrap();
}
