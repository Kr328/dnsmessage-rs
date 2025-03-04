use std::{io::Cursor, net::UdpSocket};

#[test]
fn test_query() {
    let sk = UdpSocket::bind("0.0.0.0:0").unwrap();
    sk.connect("1.1.1.1:53").unwrap();

    let pkt = dnsmessage::Builder::new(Cursor::new(Vec::with_capacity(512)))
        .unwrap()
        .write_header(dnsmessage::Header {
            id: 1145,
            resp: false,
            opcode: 0,
            rcode: dnsmessage::RCode::Success.into(),
            flags: dnsmessage::HeaderFlags::RECURSION_DESIRED,
        })
        .unwrap()
        .write_question(&dnsmessage::Question {
            name: "www.bilibili.com.",
            typ: dnsmessage::Type::A.into(),
            class: dnsmessage::Class::INET.into(),
        })
        .unwrap()
        .finish_questions()
        .unwrap()
        .finish_answers()
        .unwrap()
        .finish_authorities()
        .unwrap()
        .finish_additionals()
        .unwrap()
        .into_inner();

    sk.send(&pkt).unwrap();

    let mut buf = [0u8; 512];
    let n = sk.recv(&mut buf).unwrap();

    let pkt = dnsmessage::Packet::new(&buf[..n]).unwrap();
    for answer in pkt.answers() {
        let answer = answer.unwrap();

        match answer.data {
            dnsmessage::ResourceData::A { a } => {
                println!("addr = {:?}", a);
            }
            _ => {}
        }
    }
}
