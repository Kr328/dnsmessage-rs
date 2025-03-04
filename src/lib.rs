mod builder;
mod packet;

use std::{
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
};

use num_enum::TryFromPrimitive;

pub use crate::{builder::*, packet::*};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("short buffer")]
    ShortBuffer,

    #[error("packet size mismatch")]
    PacketSizeMismatch,

    #[error("name too long")]
    NameTooLong,

    #[error("text too long")]
    TextTooLong,

    #[error("name is not canonical")]
    NonCanonicalName,

    #[error("invalid name segment size: {0}")]
    InvalidNameSegmentSize(usize),

    #[error("invalid name segment body")]
    InvalidNameSegmentBody,

    #[error("too many pointers")]
    TooManyPointers,

    #[error("invalid cursor state")]
    InvalidCursorState,
}

bitflags::bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Hash)]
    pub struct HeaderFlags: u16 {
        const AUTHORITATIVE = 1 << 10;
        const TRUNCATED = 1 << 9;
        const RECURSION_DESIRED = 1 << 8;
        const RECURSION_AVAILABLE = 1 << 7;
        const REVERSED = 1 << 6;
        const AUTHENTIC_DATA = 1 << 5;
        const CHECKING_DISABLED = 1 << 4;
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Hash, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
pub enum RCode {
    Success = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

#[derive(Debug, Copy, Clone, PartialEq, Hash)]
pub struct Header {
    pub id: u16,
    pub resp: bool,
    pub opcode: u16,
    pub rcode: MaybeUnknown<RCode>,
    pub flags: HeaderFlags,
}

#[derive(Debug, Copy, Clone, PartialEq, Hash)]
pub enum MaybeUnknown<T: TryFromPrimitive + Into<T::Primitive>> {
    Known(T),
    Unknown(T::Primitive),
}

impl<T: TryFromPrimitive + Into<T::Primitive>> From<T> for MaybeUnknown<T> {
    fn from(value: T) -> Self {
        Self::Known(value)
    }
}

impl<T: TryFromPrimitive + Into<T::Primitive>> MaybeUnknown<T> {
    fn into(self) -> T::Primitive {
        match self {
            Self::Known(v) => v.into(),
            Self::Unknown(v) => v,
        }
    }

    fn from(value: T::Primitive) -> Self {
        match T::try_from_primitive(value) {
            Ok(v) => Self::Known(v),
            Err(_) => Self::Unknown(value),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Hash, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
pub enum Type {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    WKS = 11,
    HINFO = 13,
    MINFO = 14,
    AXFR = 252,
    ALL = 255,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Hash, num_enum::IntoPrimitive, num_enum::TryFromPrimitive)]
pub enum Class {
    INET = 1,
    CSNET = 2,
    CHAOS = 3,
    HESIOD = 4,
    ANY = 255,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Question<N> {
    pub name: N,
    pub typ: MaybeUnknown<Type>,
    pub class: MaybeUnknown<Class>,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum ResourceData<N, D> {
    A {
        a: Ipv4Addr,
    },
    NS {
        ns: N,
    },
    CNAME {
        cname: N,
    },
    SOA {
        ns: N,
        mbox: N,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        min_ttl: u32,
    },
    PTR {
        ptr: N,
    },
    MX {
        preference: u16,
        mx: N,
    },
    TXT {
        txt: Vec<D>,
    },
    AAAA {
        aaaa: Ipv6Addr,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: N,
    },
    Unknown {
        typ: MaybeUnknown<Type>,
        data: D,
    },
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Resource<N, D> {
    pub name: N,
    pub class: MaybeUnknown<Class>,
    pub ttl: u32,
    pub data: ResourceData<N, D>,
}

impl<'a> ResourceData<NameVisitor<'a>, &'a [u8]> {
    pub fn try_to_owned<N: From<String>, D: From<Vec<u8>>>(&self) -> Result<ResourceData<N, D>, Error> {
        let data = match self {
            ResourceData::A { a } => ResourceData::A { a: *a },
            ResourceData::NS { ns } => ResourceData::NS {
                ns: N::from(ns.to_string()?),
            },
            ResourceData::CNAME { cname } => ResourceData::CNAME {
                cname: N::from(cname.to_string()?),
            },
            ResourceData::SOA {
                ns,
                mbox,
                serial,
                refresh,
                retry,
                expire,
                min_ttl,
            } => ResourceData::SOA {
                ns: N::from(ns.to_string()?),
                mbox: N::from(mbox.to_string()?),
                serial: *serial,
                refresh: *refresh,
                retry: *retry,
                expire: *expire,
                min_ttl: *min_ttl,
            },
            ResourceData::PTR { ptr } => ResourceData::PTR {
                ptr: N::from(ptr.to_string()?),
            },
            ResourceData::MX { preference, mx } => ResourceData::MX {
                preference: *preference,
                mx: N::from(mx.to_string()?),
            },
            ResourceData::TXT { txt } => ResourceData::TXT {
                txt: txt.iter().map(|v| D::from(v.to_vec())).collect(),
            },
            ResourceData::AAAA { aaaa } => ResourceData::AAAA { aaaa: *aaaa },
            ResourceData::SRV {
                priority,
                weight,
                port,
                target,
            } => ResourceData::SRV {
                priority: *priority,
                weight: *weight,
                port: *port,
                target: N::from(target.to_string()?),
            },
            ResourceData::Unknown { typ, data } => ResourceData::Unknown {
                typ: *typ,
                data: D::from(data.to_vec()),
            },
        };

        Ok(data)
    }
}
