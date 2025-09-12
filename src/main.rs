use etherparse::NetSlice::Ipv4;
use etherparse::{Icmpv4Type, PacketBuilder, SlicedPacket, TransportSlice};
use std::env;
use std::io::Write;
use std::u64;
use TransportSlice::Icmpv4;

fn main() {
    // Interface to capture on must be provided via env var PCAP_IFACE
    let iface = env::var("PCAP_IFACE").expect("Set PCAP_IFACE to the interface name (e.g., eth0)");

    let mut cap = pcap::Capture::from_device(iface.as_str())
        .expect("device lookup failed")
        .promisc(true)
        .immediate_mode(true)
        .open()
        .expect("failed to open capture");

    // Only handle IPv4 ICMP to reduce overhead
    cap.filter("icmp and ip", true).ok();

    // We only support Ethernet datalink for now (no Linux cooked or others)
    let dl = cap.get_datalink();
    if dl != pcap::Linktype(1) {
        eprintln!(
            "Unsupported datalink {:?}. Please use an Ethernet interface (e.g., eth0)",
            dl
        );
        return;
    }

    loop {
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("pcap read error: {}", e);
                continue;
            }
        };
        let data = packet.data;
        if data.len() < 14 {
            continue;
        }

        // Ethernet header
        let dst_mac = &data[0..6];
        let src_mac = &data[6..12];
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            continue; // not IPv4
        }

        let slice = &data[14..];
        let packet = SlicedPacket::from_ip(slice);

        if let Ok(SlicedPacket {
            net: Some(Ipv4(ip)),
            transport: Some(Icmpv4(icmp)),
            ..
        }) = &packet
        {
            if let Icmpv4Type::EchoRequest(echo_request) = &icmp.icmp_type() {
                let new_source = ip.header().destination();
                let new_destination = ip.header().source();
                let payload = icmp.payload();

                if payload.len() < 16 {
                    // not our expected payload; still respond unchanged
                }

                let mut seconds: [u8; 8] = [0; 8];
                let mut useconds: [u8; 8] = [0; 8];
                if payload.len() >= 16 {
                    seconds.copy_from_slice(&payload[0..8]);
                    useconds.copy_from_slice(&payload[8..16]);
                }

                let mut seconds = u64::from_le_bytes(seconds);
                let mut useconds = u64::from_le_bytes(useconds);

                //seconds = seconds.saturating_sub(1);

                let to_add = 125_000;

                if useconds + to_add >= 1_000_000 {
                    seconds += 1;
                    useconds = useconds + to_add - 1_000_000;
                } else {
                    useconds += to_add;
                }

                let mut response_payload: Vec<u8> = Vec::with_capacity(payload.len());
                response_payload.write_all(payload).unwrap();
                if response_payload.len() >= 16 {
                    response_payload[0..8].copy_from_slice(&seconds.to_le_bytes());
                    response_payload[8..16].copy_from_slice(&useconds.to_le_bytes());
                }

                let new_packet = PacketBuilder::ipv4(new_source, new_destination, 255)
                    .icmpv4_echo_reply(echo_request.id, echo_request.seq);

                // Build Ethernet header (swap src/dst MACs)
                let mut response_buffer =
                    Vec::<u8>::with_capacity(14 + new_packet.size(response_payload.len()));
                // dst = original src, src = original dst
                response_buffer.extend_from_slice(src_mac);
                response_buffer.extend_from_slice(dst_mac);
                response_buffer.extend_from_slice(&0x0800u16.to_be_bytes());

                new_packet
                    .write(&mut response_buffer, &response_payload)
                    .unwrap();

                if let Err(e) = cap.sendpacket(response_buffer.as_slice()) {
                    eprintln!("sendpacket failed: {}", e);
                }
            }
        }
    }
}
