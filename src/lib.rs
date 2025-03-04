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

#[derive(Debug, thiserror::Error)]
pub enum EitherError<L, R> {
    #[error("{0}")]
    Left(L),
    #[error("{0}")]
    Right(R),
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

impl<N: TryInto<String>> Question<N> {
    pub fn try_into_owned<RN: From<String>>(self) -> Result<Question<RN>, N::Error> {
        Ok(Question {
            name: RN::from(self.name.try_into()?),
            typ: self.typ,
            class: self.class,
        })
    }
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

impl<N, D> ResourceData<N, D>
where
    N: TryInto<String>,
    D: TryInto<Vec<u8>>,
{
    pub fn try_into_owned<RN: From<String>, RD: From<Vec<u8>>>(
        self,
    ) -> Result<ResourceData<RN, RD>, EitherError<N::Error, D::Error>> {
        let data = match self {
            ResourceData::A { a } => ResourceData::A { a },
            ResourceData::NS { ns } => ResourceData::NS {
                ns: RN::from(ns.try_into().map_err(|err| EitherError::Left(err))?),
            },
            ResourceData::CNAME { cname } => ResourceData::CNAME {
                cname: RN::from(cname.try_into().map_err(|err| EitherError::Left(err))?),
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
                ns: RN::from(ns.try_into().map_err(|err| EitherError::Left(err))?),
                mbox: RN::from(mbox.try_into().map_err(|err| EitherError::Left(err))?),
                serial,
                refresh,
                retry,
                expire,
                min_ttl,
            },
            ResourceData::PTR { ptr } => ResourceData::PTR {
                ptr: RN::from(ptr.try_into().map_err(|err| EitherError::Left(err))?),
            },
            ResourceData::MX { preference, mx } => ResourceData::MX {
                preference,
                mx: RN::from(mx.try_into().map_err(|err| EitherError::Left(err))?),
            },
            ResourceData::TXT { txt } => {
                let mut new_txt = Vec::with_capacity(txt.len());

                for t in txt {
                    new_txt.push(RD::from(t.try_into().map_err(|err| EitherError::Right(err))?));
                }

                ResourceData::TXT { txt: new_txt }
            }
            ResourceData::AAAA { aaaa } => ResourceData::AAAA { aaaa },
            ResourceData::SRV {
                priority,
                weight,
                port,
                target,
            } => ResourceData::SRV {
                priority,
                weight,
                port,
                target: RN::from(target.try_into().map_err(|err| EitherError::Left(err))?),
            },
            ResourceData::Unknown { typ, data } => ResourceData::Unknown {
                typ,
                data: RD::from(data.try_into().map_err(|err| EitherError::Right(err))?),
            },
        };

        Ok(data)
    }
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Resource<N, D> {
    pub name: N,
    pub class: MaybeUnknown<Class>,
    pub ttl: u32,
    pub data: ResourceData<N, D>,
}

impl<N, D> Resource<N, D>
where
    N: TryInto<String>,
    D: TryInto<Vec<u8>>,
{
    pub fn try_into_owned<RN: From<String>, RD: From<Vec<u8>>>(
        self,
    ) -> Result<Resource<RN, RD>, EitherError<N::Error, D::Error>> {
        Ok(Resource {
            name: RN::from(self.name.try_into().map_err(|err| EitherError::Left(err))?),
            class: self.class,
            ttl: self.ttl,
            data: self.data.try_into_owned()?,
        })
    }
}
