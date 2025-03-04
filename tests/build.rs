use std::{
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr},
};

#[test]
fn test_build_packet() {
    let pkt = dnsmessage::Builder::new(Cursor::new(Vec::new()))
        .unwrap()
        .write_header(dnsmessage::Header {
            id: 114,
            resp: true,
            opcode: 0,
            rcode: dnsmessage::RCode::Refused.into(),
            flags: dnsmessage::HeaderFlags::RECURSION_DESIRED | dnsmessage::HeaderFlags::RECURSION_AVAILABLE,
        })
        .unwrap()
        .write_question(&dnsmessage::Question {
            name: "www.example.org.",
            typ: dnsmessage::Type::AAAA.into(),
            class: dnsmessage::Class::INET.into(),
        })
        .unwrap()
        .write_question(&dnsmessage::Question {
            name: "example.org.",
            typ: dnsmessage::Type::AAAA.into(),
            class: dnsmessage::Class::INET.into(),
        })
        .unwrap()
        .finish_questions()
        .unwrap()
        .write_answer(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::AAAA {
                aaaa: Ipv6Addr::from([1u16, 2, 3, 4, 5, 6, 7, 8]),
            },
        })
        .unwrap()
        .write_answer(&dnsmessage::Resource::<_, &[u8]> {
            name: "example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::AAAA {
                aaaa: Ipv6Addr::from([9u16, 10, 11, 12, 13, 14, 15, 16]),
            },
        })
        .unwrap()
        .write_answer(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::AAAA {
                aaaa: Ipv6Addr::from([17u16, 18, 19, 20, 21, 22, 23, 24]),
            },
        })
        .unwrap()
        .write_answer(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::CNAME { cname: "example.org." },
        })
        .unwrap()
        .finish_answers()
        .unwrap()
        .write_authority(&dnsmessage::Resource::<_, &[u8]> {
            name: "example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::NS { ns: "ns.example.org." },
        })
        .unwrap()
        .finish_authorities()
        .unwrap()
        .write_additional(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::A {
                a: Ipv4Addr::from([1u8, 2, 3, 4]),
            },
        })
        .unwrap()
        .write_additional(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::SOA {
                ns: "ns.example.org.",
                mbox: "example.org.",
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                min_ttl: 5,
            },
        })
        .unwrap()
        .write_additional(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::PTR { ptr: "ptr.example.org." },
        })
        .unwrap()
        .write_additional(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::MX {
                preference: 8,
                mx: "mx.example.org.",
            },
        })
        .unwrap()
        .write_additional(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::TXT {
                txt: vec![b"114514", b"1919810"],
            },
        })
        .unwrap()
        .write_additional(&dnsmessage::Resource::<_, &[u8]> {
            name: "www.example.org.",
            class: dnsmessage::Class::INET.into(),
            ttl: 255,
            data: dnsmessage::ResourceData::SRV {
                priority: 9,
                weight: 10,
                port: 11,
                target: "12.example.org.",
            },
        })
        .unwrap()
        .finish_additionals()
        .unwrap()
        .into_inner();

    let pkt = simple_dns::Packet::parse(&pkt).unwrap();
    assert_eq!(pkt.id(), 114);
    assert!(pkt.has_flags(simple_dns::PacketFlag::RESPONSE));
    assert!(pkt.has_flags(simple_dns::PacketFlag::RECURSION_DESIRED));
    assert!(pkt.has_flags(simple_dns::PacketFlag::RECURSION_AVAILABLE));

    assert_eq!(pkt.questions.len(), 2);
    assert_eq!(pkt.questions[0].qname.to_string(), "www.example.org");
    assert_eq!(pkt.questions[0].qclass, simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN));
    assert_eq!(pkt.questions[0].qtype, simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA));
    assert_eq!(pkt.questions[1].qname.to_string(), "example.org");
    assert_eq!(pkt.questions[1].qclass, simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN));
    assert_eq!(pkt.questions[1].qtype, simple_dns::QTYPE::TYPE(simple_dns::TYPE::AAAA));

    assert_eq!(pkt.answers.len(), 4);
    assert_eq!(pkt.answers[0].name.to_string(), "www.example.org");
    assert_eq!(pkt.answers[0].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.answers[0].ttl, 255);
    assert_eq!(
        pkt.answers[0].rdata,
        simple_dns::rdata::RData::AAAA(simple_dns::rdata::AAAA::from(Ipv6Addr::from([1u16, 2, 3, 4, 5, 6, 7, 8])))
    );
    assert_eq!(pkt.answers[1].name.to_string(), "example.org");
    assert_eq!(pkt.answers[1].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.answers[1].ttl, 255);
    assert_eq!(
        pkt.answers[1].rdata,
        simple_dns::rdata::RData::AAAA(simple_dns::rdata::AAAA::from(Ipv6Addr::from([
            9u16, 10, 11, 12, 13, 14, 15, 16
        ])))
    );
    assert_eq!(pkt.answers[2].name.to_string(), "www.example.org");
    assert_eq!(pkt.answers[2].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.answers[2].ttl, 255);
    assert_eq!(
        pkt.answers[2].rdata,
        simple_dns::rdata::RData::AAAA(simple_dns::rdata::AAAA::from(Ipv6Addr::from([
            17u16, 18, 19, 20, 21, 22, 23, 24
        ])))
    );
    assert_eq!(pkt.answers[3].name.to_string(), "www.example.org");
    assert_eq!(pkt.answers[3].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.answers[3].ttl, 255);
    assert_eq!(
        pkt.answers[3].rdata,
        simple_dns::rdata::RData::CNAME(simple_dns::rdata::CNAME::from(simple_dns::Name::new("example.org").unwrap()))
    );

    assert_eq!(pkt.name_servers.len(), 1);
    assert_eq!(pkt.name_servers[0].name.to_string(), "example.org");
    assert_eq!(pkt.name_servers[0].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.name_servers[0].ttl, 255);
    assert_eq!(
        pkt.name_servers[0].rdata,
        simple_dns::rdata::RData::NS(simple_dns::rdata::NS::from(simple_dns::Name::new("ns.example.org").unwrap()))
    );

    assert_eq!(pkt.additional_records.len(), 6);
    assert_eq!(pkt.additional_records[0].name.to_string(), "www.example.org");
    assert_eq!(pkt.additional_records[0].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.additional_records[0].ttl, 255);
    assert_eq!(
        pkt.additional_records[0].rdata,
        simple_dns::rdata::RData::A(simple_dns::rdata::A::from(Ipv4Addr::from([1u8, 2, 3, 4])))
    );
    assert_eq!(pkt.additional_records[1].name.to_string(), "www.example.org");
    assert_eq!(pkt.additional_records[1].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.additional_records[1].ttl, 255);
    assert_eq!(
        pkt.additional_records[1].rdata,
        simple_dns::rdata::RData::SOA(simple_dns::rdata::SOA {
            mname: simple_dns::Name::new("ns.example.org").unwrap(),
            rname: simple_dns::Name::new("example.org").unwrap(),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        })
    );
    assert_eq!(pkt.additional_records[2].name.to_string(), "www.example.org");
    assert_eq!(pkt.additional_records[2].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.additional_records[2].ttl, 255);
    assert_eq!(
        pkt.additional_records[2].rdata,
        simple_dns::rdata::RData::PTR(simple_dns::rdata::PTR::from(
            simple_dns::Name::new("ptr.example.org").unwrap()
        ))
    );
    assert_eq!(pkt.additional_records[3].name.to_string(), "www.example.org");
    assert_eq!(pkt.additional_records[3].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.additional_records[3].ttl, 255);
    assert_eq!(
        pkt.additional_records[3].rdata,
        simple_dns::rdata::RData::MX(simple_dns::rdata::MX {
            preference: 8,
            exchange: simple_dns::Name::new("mx.example.org").unwrap(),
        })
    );
    assert_eq!(pkt.additional_records[4].name.to_string(), "www.example.org");
    assert_eq!(pkt.additional_records[4].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.additional_records[4].ttl, 255);
    assert_eq!(
        pkt.additional_records[4].rdata,
        simple_dns::rdata::RData::TXT({
            let mut txt = simple_dns::rdata::TXT::new();
            txt.add_string("114514").unwrap();
            txt.add_string("1919810").unwrap();
            txt
        })
    );
    assert_eq!(pkt.additional_records[5].name.to_string(), "www.example.org");
    assert_eq!(pkt.additional_records[5].class, simple_dns::CLASS::IN);
    assert_eq!(pkt.additional_records[5].ttl, 255);
    assert_eq!(
        pkt.additional_records[5].rdata,
        simple_dns::rdata::RData::SRV(simple_dns::rdata::SRV {
            priority: 9,
            weight: 10,
            port: 11,
            target: simple_dns::Name::new("12.example.org").unwrap(),
        })
    );
}
