use std::fs::File;
use std::io::Read;
use std::error::Error;

use packets::{BytePacketBuffer, DnsPacket};

mod packets;
mod header;
mod record;

fn main() -> Result<(), Box<dyn Error>> {
    let mut f = File::open("test/response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }


    Ok(())
}
