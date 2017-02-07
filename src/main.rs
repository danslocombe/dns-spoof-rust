extern crate argparse;
extern crate pnet;

use argparse::{ArgumentParser, Store, StoreTrue};

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket, EtherType};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::udp::UdpPacket;

use std::process::exit;
use std::mem::transmute;

fn main() {

    //  Options
    let mut target_interface : String = "eth0".to_string();
    let mut domain_name : String = "".to_string();
    let mut ip_redirect : String = "".to_string();

    //  Parse arguments
    {
        let mut argparse = ArgumentParser::new();
        argparse.set_description("DNS spoofer");
        argparse.refer(&mut target_interface)
            .add_option(&["-i", "--interface"], Store,
            "Specify an interface");
        argparse.refer(&mut domain_name)
            .add_argument("domain_name", Store,
            "Domain to spoof");
        argparse.refer(&mut ip_redirect)
            .add_argument("ip_redirect", Store,
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
    let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    let mut iter = rx.iter();


    loop {
        match iter.next() {
            Ok(eth) => {
                let maybe_ipv4 : Option<Ipv4Packet>
                    =   unwrap_eth(&eth);

                let maybe_ipv4_udp : Option<(&Ipv4Packet, UdpPacket)>
                    =   maybe_ipv4.as_ref().and_then(unwrap_ipv4);

                //  Construct closure with the redirect ip and domain_name
                let process_udp_with_redirect = |x| {
                    process_ipv4_udp(&domain_name, &ip_redirect, x)
                };

                let to_send : Option<Ipv4Packet>
                    =   maybe_ipv4_udp.as_ref().and_then(process_udp_with_redirect);
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

fn process_ipv4_udp<'t>(domain_name : &String, ip_redirect : &String, a : &'t (&'t Ipv4Packet<'t>, UdpPacket<'t>)) -> Option<Ipv4Packet<'t>> {
    let (ipv4_ref, ref udp) : (&Ipv4Packet, UdpPacket) = *a; 
    process_packet(ipv4_ref, &udp, domain_name, ip_redirect)
}
fn process_packet<'t>(ipv4 : &'t Ipv4Packet, udp : &'t UdpPacket, name_redirect : &String, ip_redirect : &String) -> Option<Ipv4Packet<'t>>{
    println!("Got packet {} -> {}", ipv4.get_source(), ipv4.get_destination());
    //  Assume for now is dns
    //  TODO check array access, malformed packet will crash program
    //  TODO truncation
    let dns_data : &[ u8 ] = udp.payload();

    let id = build_u16(dns_data, 0);
    if id == 0 {return None;}
    println!("Id {:X}", id);

    let flags = build_u16(dns_data, 2);
    println!("flags {:X}", flags);
    let is_query = (flags & 0x8000) != 0;
    println!("is query {}", is_query);

    let query_count = build_u16(dns_data, 4);
    println!("query count {}", query_count);
    //  We only reply to packets with exactly one request
    if query_count != 1 {return None;}

    print!("All data: ");
    for datum in dns_data {
        print!("{:X} ", datum);
    }

    let domain_name = get_domain_name(dns_data, 12);

    domain_name.as_ref().and_then(|dn| {
        print!("\n domain name : {} END", dn);
        if dn == name_redirect {
            println!("\nMatchin Domain, redirecting to {}", ip_redirect);
            None
        }
        else {
            None
        }
    })
}

fn get_domain_name(data : &[ u8 ], start : usize) -> Option<String>{
    let mut name = "".to_owned();
    let mut cur = start;
    let mut first : bool = true;
    for _ in 1..64 {
        if (data).len() < cur {return None;}
        let length = data[cur] as usize;

        if (data).len() < cur + length {return None;}

        cur = cur + 1;
        println!("length = {}", length);
        if length == 0 {
            println!("End of domain");
            break;
        }
        //  TODO refactor
        if !first {
            name.push('.');
        }
        else {
            first = false;
        }
        let str_end = cur + (length as usize);
        for i in cur..str_end {
            print!("i={} {:X} ", i, data[i]);
            name.push(data[i] as char);
        }
	    cur = str_end;
    }

    println!("Domain : {}", name);
    Some (name)
}


fn build_u16(bytes : &[u8], index : usize) -> u16 {
    unsafe {transmute::<[u8; 2], u16> ([bytes[index], bytes[index + 1]]) }.to_be()
}

