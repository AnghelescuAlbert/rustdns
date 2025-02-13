use std::error::Error;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::UdpSocket;


use dnsrust::record::DnsQuestion;
use dnsrust::record::QueryType;
use dnsrust::packets::{BytePacketBuffer, DnsPacket};
use dnsrust::header::ResultCode;

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16))
    -> Result<DnsPacket, Box<dyn Error>> {

        let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
    
        let mut packet = DnsPacket::new();
    
        packet.header.id = 6666;
        packet.header.questions = 1;
        packet.header.recursion_desired = true;
        packet
            .questions
            .push(DnsQuestion::new(qname.to_string(), qtype));
    
        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;
    
        let mut res_buffer = BytePacketBuffer::new();
        socket.recv_from(&mut res_buffer.buf)?;
    
        DnsPacket::from_buffer(&mut res_buffer)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket, Box<dyn Error>> {
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response);
        }

        // We might also get a NXDOMAIN reply, which is the authoritative name servers
        // way of telling that the name doesn't exist

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;

            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }

    }
}

// Handle a single incoming packet
fn handle_query(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let mut req_buffer = BytePacketBuffer::new();

    // Te 'recv_from' function will write the data into the buffer,
    // and return the length of the data read as well as the source address.
    // We need to keep track of the source in order to send our reply later.

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    // Parsing the raw bytes into a 'DnsPacket'
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    // Create the response packet
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    // In the normal case, exactly one question is present
    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);
        // There's always the possibility that the query will fail, in which
        // case the 'SERVFAIL' response code is set to indicate as much to the client.
        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            packet.questions.push(question.clone());
            packet.header.rescode = result.header.rescode;
    
            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
    
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
    
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                packet.resources.push(rec);
            }
        } else {
            packet.header.rescode = ResultCode::SERVFAIL;
        }
    } else {
        packet.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {

    let socket = UdpSocket::bind(("127.0.0.1", 2053))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprint!("An error ocurred: {}", e),
        }
    }
}