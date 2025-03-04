use std::{io::Cursor, net::Ipv4Addr};

#[test]
fn test_modify() {
    let pkt = dnsmessage::Builder::new(Cursor::new(Vec::new()))
        .unwrap()
        .write_header(dnsmessage::Header {
            id: 1145,
            resp: false,
            opcode: 0,
            rcode: dnsmessage::RCode::Success.into(),
            flags: dnsmessage::HeaderFlags::RECURSION_DESIRED | dnsmessage::HeaderFlags::RECURSION_AVAILABLE,
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
        .write_answer(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.bilibili.com.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::A { a: Ipv4Addr::LOCALHOST },
        })
        .unwrap()
        .write_answer(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.bilibili.com.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::A { a: Ipv4Addr::BROADCAST },
        })
        .unwrap()
        .finish_answers()
        .unwrap()
        .finish_authorities()
        .unwrap()
        .finish_additionals()
        .unwrap()
        .into_inner();

    let mut pkt = dnsmessage::Packet::new(pkt).unwrap();

    let mut answers_cursor = pkt.answers_cursor();
    while let Ok(true) = answers_cursor.next() {
        answers_cursor.set_ttl(1).unwrap();
    }

    let pkt = dnsmessage::Packet::new(pkt.into_inner()).unwrap();
    let mut answers = pkt.answers();
    let answer = answers.next().unwrap().unwrap();
    assert_eq!(answer.ttl, 1);
    assert_eq!(answer.data, dnsmessage::ResourceData::A { a: Ipv4Addr::LOCALHOST });
    let answer = answers.next().unwrap().unwrap();
    assert_eq!(answer.ttl, 1);
    assert_eq!(answer.data, dnsmessage::ResourceData::A { a: Ipv4Addr::BROADCAST });
    assert!(answers.next().is_none());
}
