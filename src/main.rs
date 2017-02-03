extern crate argparse;
extern crate pnet;

use argparse::{ArgumentParser, Store, StoreTrue};

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EthernetPacket, EtherType};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::udp::UdpPacket;

use std::process::exit;
use std::mem::transmute;

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

                //maybe_ipv4.map(|&ipv4| {println!("{} -> {}", ipv4.get_source(), ipv4.get_destination());});

                let maybe_ipv4_udp : Option<(&Ipv4Packet, UdpPacket)>
                    = match maybe_ipv4 {
                        Some(ref ipv4) => {
                            unwrap_ipv4(&ipv4)
                        }
                        None => {
                            None
                        }
                    };
                let to_send : Option<Ipv4Packet>
                    = match maybe_ipv4_udp {
                        Some((ipv4_ref, ref udp)) => {
                            process_packet(ipv4_ref, udp)
                        }
                        None => {None}
                    };
			}	
			Err(e) => {
				panic!("An error occurred reading packet: {}", e);
			}
		}

	}


}

const IPV4_PROTOCOL_ID : u16 = 0x0800;

fn unwrap_eth<'p>(eth : &'p EthernetPacket) -> Option<Ipv4Packet<'p>>{
    match eth.get_ethertype() {
        EtherType(IPV4_PROTOCOL_ID) => {
            Ipv4Packet::new(eth.payload())
        }
        _ => { None }
    }
}

const UDP_PROTOCOL_ID : u8 = 17;

fn unwrap_ipv4<'p>(ipv4 : &'p Ipv4Packet) -> Option<(&'p Ipv4Packet<'p>, UdpPacket<'p>)>{
    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocol(UDP_PROTOCOL_ID) => {
            UdpPacket::new(ipv4.payload()).map(|udp| (ipv4, udp))
        }
        _ => { None }
    }
}

fn process_packet<'t>(ipv4 : &'t Ipv4Packet, udp : &'t UdpPacket) -> Option<Ipv4Packet<'t>>{
	println!("Got packet {} -> {}", ipv4.get_source(), ipv4.get_destination());
    //  Assume for now is dns
    let dns_data : &[ u8 ] = udp.payload();

    let id = build_u16(dns_data, 0);
    if (id == 0) {return None;}
    println!("Id {:X}", id);

    let flags = build_u16(dns_data, 2);
    println!("flags {:X}", flags);
    let is_query = (flags & 0x8000) != 0;
    println!("is query {}", is_query);

    let query_count = build_u16(dns_data, 4);
    println!("full data {:?}", query_count);



    None
}

fn build_u16(bytes : &[u8], index : usize) -> u16 {
    unsafe {transmute::<[u8; 2], u16> ([bytes[index], bytes[index + 1]]) }.to_be()
}

struct Dns {

}

/*
fn is_dns(&packet : UdpPacket) -> bool{
	true
}

*/
