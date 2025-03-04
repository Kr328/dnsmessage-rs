use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

#[test]
fn test_parse() {
    let mut pkt = simple_dns::Packet::new_reply(8899);
    pkt.set_flags(simple_dns::PacketFlag::RECURSION_DESIRED | simple_dns::PacketFlag::RECURSION_AVAILABLE);
    pkt.questions = vec![
        simple_dns::Question::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::TYPE::AAAA.into(),
            simple_dns::CLASS::IN.into(),
            false,
        ),
        simple_dns::Question::new(
            simple_dns::Name::new("example.org").unwrap(),
            simple_dns::TYPE::AAAA.into(),
            simple_dns::CLASS::IN.into(),
            false,
        ),
    ];
    pkt.answers = vec![
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::AAAA(simple_dns::rdata::AAAA::from(Ipv6Addr::from([1u16, 2, 3, 4, 5, 6, 7, 8]))),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::AAAA(simple_dns::rdata::AAAA::from(Ipv6Addr::from([
                9u16, 10, 11, 12, 13, 14, 15, 16,
            ]))),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::AAAA(simple_dns::rdata::AAAA::from(Ipv6Addr::from([
                17u16, 18, 19, 20, 21, 22, 23, 24,
            ]))),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::CNAME(simple_dns::rdata::CNAME::from(simple_dns::Name::new("example.org").unwrap())),
        ),
    ];
    pkt.name_servers = vec![simple_dns::ResourceRecord::new(
        simple_dns::Name::new("example.org").unwrap(),
        simple_dns::CLASS::IN.into(),
        255,
        simple_dns::rdata::RData::NS(simple_dns::rdata::NS::from(simple_dns::Name::new("ns.example.org").unwrap())),
    )];
    pkt.additional_records = vec![
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::A(simple_dns::rdata::A::from(Ipv4Addr::from([1u8, 2, 3, 4]))),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::SOA(simple_dns::rdata::SOA {
                mname: simple_dns::Name::new("ns.example.org").unwrap(),
                rname: simple_dns::Name::new("example.org").unwrap(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            }),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::PTR(simple_dns::rdata::PTR::from(
                simple_dns::Name::new("ptr.example.org").unwrap(),
            )),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::MX(simple_dns::rdata::MX {
                preference: 8,
                exchange: simple_dns::Name::new("mx.example.org").unwrap(),
            }),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::TXT({
                let mut txt = simple_dns::rdata::TXT::new();
                txt.add_string("114514").unwrap();
                txt.add_string("1919810").unwrap();
                txt
            }),
        ),
        simple_dns::ResourceRecord::new(
            simple_dns::Name::new("www.example.org").unwrap(),
            simple_dns::CLASS::IN.into(),
            255,
            simple_dns::rdata::RData::SRV(simple_dns::rdata::SRV {
                priority: 9,
                weight: 10,
                port: 11,
                target: simple_dns::Name::new("12.example.org").unwrap(),
            }),
        ),
    ];

    let pkt = pkt.build_bytes_vec_compressed().unwrap();

    let pkt = dnsmessage::Packet::new(pkt).unwrap();

    let mut questions = pkt.questions();
    let question = questions.next().unwrap().unwrap();
    assert_eq!(question.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(question.typ, dnsmessage::Type::AAAA.into());
    assert_eq!(question.class, dnsmessage::Class::INET.into());
    let question = questions.next().unwrap().unwrap();
    assert_eq!(question.name.to_string().unwrap(), "example.org.");
    assert_eq!(question.typ, dnsmessage::Type::AAAA.into());
    assert_eq!(question.class, dnsmessage::Class::INET.into());
    assert!(questions.next().is_none());

    let mut answers = pkt.answers();
    let answer = answers.next().unwrap().unwrap();
    assert_eq!(answer.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(answer.class, dnsmessage::Class::INET.into());
    assert_eq!(answer.ttl, 255);
    assert_eq!(
        answer.data,
        dnsmessage::ResourceData::AAAA {
            aaaa: Ipv6Addr::from([1u16, 2, 3, 4, 5, 6, 7, 8])
        }
    );
    let answer = answers.next().unwrap().unwrap();
    assert_eq!(answer.name.to_string().unwrap(), "example.org.");
    assert_eq!(answer.class, dnsmessage::Class::INET.into());
    assert_eq!(answer.ttl, 255);
    assert_eq!(
        answer.data,
        dnsmessage::ResourceData::AAAA {
            aaaa: Ipv6Addr::from([9u16, 10, 11, 12, 13, 14, 15, 16])
        }
    );
    let answer = answers.next().unwrap().unwrap();
    assert_eq!(answer.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(answer.class, dnsmessage::Class::INET.into());
    assert_eq!(answer.ttl, 255);
    assert_eq!(
        answer.data,
        dnsmessage::ResourceData::AAAA {
            aaaa: Ipv6Addr::from([17u16, 18, 19, 20, 21, 22, 23, 24])
        }
    );
    let answer = answers.next().unwrap().unwrap();
    assert_eq!(answer.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(answer.class, dnsmessage::Class::INET.into());
    assert_eq!(answer.ttl, 255);
    assert_eq!(
        answer.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::CNAME {
            cname: Cow::Borrowed("example.org.")
        }
    );
    assert!(answers.next().is_none());

    let mut authorities = pkt.authorities();
    let authority = authorities.next().unwrap().unwrap();
    assert_eq!(authority.name.to_string().unwrap(), "example.org.");
    assert_eq!(authority.class, dnsmessage::Class::INET.into());
    assert_eq!(authority.ttl, 255);
    assert_eq!(
        authority.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::NS {
            ns: Cow::Borrowed("ns.example.org.")
        }
    );

    let mut additionals = pkt.additionals();
    let additional = additionals.next().unwrap().unwrap();
    assert_eq!(additional.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(additional.class, dnsmessage::Class::INET.into());
    assert_eq!(additional.ttl, 255);
    assert_eq!(
        additional.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::A {
            a: Ipv4Addr::from([1u8, 2, 3, 4])
        }
    );
    let additional = additionals.next().unwrap().unwrap();
    assert_eq!(additional.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(additional.class, dnsmessage::Class::INET.into());
    assert_eq!(additional.ttl, 255);
    assert_eq!(
        additional.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::SOA {
            ns: Cow::Borrowed("ns.example.org."),
            mbox: Cow::Borrowed("example.org."),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            min_ttl: 5,
        }
    );
    let additional = additionals.next().unwrap().unwrap();
    assert_eq!(additional.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(additional.class, dnsmessage::Class::INET.into());
    assert_eq!(additional.ttl, 255);
    assert_eq!(
        additional.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::PTR {
            ptr: Cow::Borrowed("ptr.example.org."),
        }
    );
    let additional = additionals.next().unwrap().unwrap();
    assert_eq!(additional.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(additional.class, dnsmessage::Class::INET.into());
    assert_eq!(additional.ttl, 255);
    assert_eq!(
        additional.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::MX {
            preference: 8,
            mx: Cow::Borrowed("mx.example.org."),
        }
    );
    let additional = additionals.next().unwrap().unwrap();
    assert_eq!(additional.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(additional.class, dnsmessage::Class::INET.into());
    assert_eq!(additional.ttl, 255);
    assert_eq!(
        additional.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::TXT {
            txt: vec![Cow::Borrowed(&b"114514"[..]), Cow::Borrowed(&b"1919810"[..])],
        }
    );
    let additional = additionals.next().unwrap().unwrap();
    assert_eq!(additional.name.to_string().unwrap(), "www.example.org.");
    assert_eq!(additional.class, dnsmessage::Class::INET.into());
    assert_eq!(additional.ttl, 255);
    assert_eq!(
        additional.data.try_to_owned::<Cow<str>, Cow<[u8]>>().unwrap(),
        dnsmessage::ResourceData::SRV {
            priority: 9,
            weight: 10,
            port: 11,
            target: Cow::Borrowed("12.example.org."),
        }
    );
    assert!(additionals.next().is_none());
}
