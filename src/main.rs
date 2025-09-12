use etherparse::NetSlice::Ipv4;
use etherparse::{Icmpv4Type, PacketBuilder, SlicedPacket, TransportSlice};
use std::io::{Read, Write};
use tun::platform::Device;
use TransportSlice::Icmpv4;


fn main() {

    let mut dev = open_tun();
    let mut buf = [0; 4096];

    loop {
        let amount = dev.read(&mut buf).unwrap();
        let slice = &buf[4..amount];

        let packet = SlicedPacket::from_ip(slice);

        if let Ok(SlicedPacket {
            net: Some(Ipv4(ip)),
            transport: Some(Icmpv4(icmp)),
            ..
        }) = &packet
        {
            if let Icmpv4Type::EchoRequest(echo_request) = &icmp.icmp_type() {
                let tun_header = &buf[0..4];
                let new_source = ip.header().destination();
                let new_destination = ip.header().source();
                let payload = icmp.payload();

                let new_packet = PacketBuilder::ipv4(new_source, new_destination, 255)
                    .icmpv4_echo_reply(echo_request.id, echo_request.seq);

                let mut response_buffer = Vec::<u8>::with_capacity(tun_header.len() + new_packet.size(payload.len()));
                response_buffer.write_all(tun_header).unwrap();
                new_packet.write(&mut response_buffer, payload).unwrap();

                dev.write_all(&response_buffer).unwrap();
            }
        }
    }
}

fn open_tun() -> Device {
    let mut config = tun::Configuration::default();
    config
        .address((169, 254, 0, 1))
        .netmask((255, 255, 255, 0))
        .up();

    config.platform(|config| {
        config.packet_information(true);
    });

    tun::create(&config).unwrap()
}
