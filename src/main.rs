extern crate argparse;
extern crate pnet;

use argparse::{ArgumentParser, Store, StoreTrue};

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;

use std::process::exit;

fn main() {

    //  Options
    let mut target_interface : String = "eth0".to_string();
    let mut domain : String = "".to_string();
    let mut target_ip : String = "".to_string();

    //  Parse arguments
    {
        let mut argparse = ArgumentParser::new();
        argparse.set_description("DNS spoofer");
        argparse.refer(&mut target_interface)
            .add_option(&["-i", "--interface"], Store,
            "Specify an interface");
        argparse.refer(&mut domain)
            .add_argument("domain", Store,
            "Domain to spoof");
        argparse.refer(&mut target_ip)
            .add_argument("target_ip", Store,
            "Target IP address");
        argparse.parse_args_or_exit();
    }

    let matches_interface = 
        |i : &NetworkInterface| {i.name == target_interface};

    let interface : NetworkInterface;

    match datalink::interfaces()
                   .into_iter()
                   .filter(matches_interface)
                   .next(){
        Some(iface) => {
            println!("Found interface {}", iface.name);
            interface = iface;
        }
        None => {
            println!("Could not find interface {}", target_interface);
            exit(1);
        }
    }


	// Create a new channel, transporting layer 2 packets
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

	let mut iter = rx.iter();

	loop {
		match iter.next() {
			Ok(eth) => {
                //  TODO monadic chaining
                let lifetimes = &eth;
                let maybe_ipv4 : Option<Ipv4Packet> = unwrap_eth(lifetimes);
                let maybe_ipv4_udp : Option<(&Ipv4Packet, UdpPacket)>
                    = match maybe_ipv4 {
                        Some(ref ipv4) => {
                            unwrap_ipv4(&ipv4)
                        }
                        None => {
                            None
                        }
                    };
                let to_send : Option<Ipv4Packet>;
                maybe_ipv4_udp.map(
                    |(ipv4_ref, udp)| {
                    process_packet(ipv4_ref, &udp)
                });
			}	
			Err(e) => {
				panic!("An error occurred reading packet: {}", e);
			}
		}

	}


}

fn unwrap_eth<'p>(eth : &'p EthernetPacket) -> Option<Ipv4Packet<'p>>{
    Ipv4Packet::new(eth.payload())
}

fn unwrap_ipv4<'p>(ipv4 : &'p Ipv4Packet) -> Option<(&'p Ipv4Packet<'p>, UdpPacket<'p>)>{
    UdpPacket::new(ipv4.payload()).map(|udp| (ipv4, udp))
}

fn process_packet(ipv4 : &Ipv4Packet, udp : &UdpPacket){
	println!("Got packet from {}, to {}", ipv4.get_source(), ipv4.get_destination());
}

fn is_dns(packet : UdpPacket) -> bool{
	true
}

