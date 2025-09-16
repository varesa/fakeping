use etherparse::NetSlice::Ipv4;
use etherparse::{Icmpv4Type, PacketBuilder, SlicedPacket, TransportSlice::Icmpv4};
use etherparse::LinkSlice::Ethernet2;
use std::env;
use std::io::Write;

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
        let packet = SlicedPacket::from_ethernet(packet.data);

        if let Ok(SlicedPacket {
            link: Some(Ethernet2(eth)),
            net: Some(Ipv4(ip)),
            transport: Some(Icmpv4(icmp)),
            ..
        }) = &packet
        {
            if let Icmpv4Type::EchoRequest(echo_request) = &icmp.icmp_type() {
                let new_source = ip.header().destination();
                let new_destination = ip.header().source();
                let payload = icmp.payload();

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

                let orig_src_mac = eth.source();
                let orig_dst_mac = eth.destination();

                let header_builder = PacketBuilder::ethernet2(orig_dst_mac, orig_src_mac)
                    .ipv4(new_source, new_destination, 255)
                    .icmpv4_echo_reply(echo_request.id, echo_request.seq);

                let mut response_buffer = Vec::<u8>::with_capacity(header_builder.size(response_payload.len()));
                header_builder
                    .write(&mut response_buffer, &response_payload)
                    .unwrap();

                if let Err(e) = cap.sendpacket(response_buffer.as_slice()) {
                    eprintln!("sendpacket failed: {}", e);
                }
            }
        }
    }
}
