use std::{
    borrow::Cow,
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

use crate::{Class, Error, Header, HeaderFlags, MaybeUnknown, Question, Resource, ResourceData, Type};

fn load_bytes<const N: usize>(buffers: &[u8], offset: usize, limit: Option<usize>) -> Result<[u8; N], Error> {
    if buffers.len() < offset + N {
        return Err(Error::ShortBuffer);
    }

    if let Some(limit) = limit {
        if offset + N > limit {
            return Err(Error::PacketSizeMismatch);
        }
    }

    <[u8; N]>::try_from(&buffers[offset..offset + N]).map_err(|_| Error::ShortBuffer)
}

fn store_bytes<const N: usize>(buffers: &mut [u8], offset: usize, bytes: [u8; N]) -> Result<(), Error> {
    if buffers.len() < offset + N {
        return Err(Error::ShortBuffer);
    }

    buffers[offset..offset + N].copy_from_slice(&bytes);

    Ok(())
}

fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize, Error> {
    loop {
        let len_or_ptr = load_bytes::<1>(packet, offset, None)?[0];

        match len_or_ptr & 0b1100_0000 {
            0b1100_0000 => break Ok(offset + 2),
            0b0000_0000 => {
                if len_or_ptr == 0 {
                    break Ok(offset + 1);
                }

                offset += 1 + len_or_ptr as usize;
            }
            _ => {
                return Err(Error::InvalidNameSegmentBody);
            }
        }
    }
}

fn skip_question(packet: &[u8], mut offset: usize) -> Result<usize, Error> {
    offset = skip_name(packet, offset)?;
    offset += 2; // Type
    offset += 2; // Class
    Ok(offset)
}

fn skip_resource(packet: &[u8], mut offset: usize) -> Result<usize, Error> {
    offset = skip_name(packet, offset)?;
    offset += 2; // Type
    offset += 2; // Class
    offset += 4; // TTL

    // Data length
    let len = u16::from_be_bytes(load_bytes(packet, offset, None)?) as usize;
    offset += 2;

    // Data
    offset += len;

    Ok(offset)
}

struct Sections {
    questions: u16,
    questions_offset: usize,
    answers: u16,
    answers_offset: usize,
    authorities: u16,
    authorities_offset: usize,
    additionals: u16,
    additionals_offset: usize,
}

fn collect_sections(packet: &[u8]) -> Result<(Sections, usize), Error> {
    let mut offset = 4;

    let questions = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let answers = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let authorities = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let additionals = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let questions_offset = offset;
    for _ in 0..questions {
        offset = skip_question(packet, offset)?;
    }

    let answers_offset = offset;
    for _ in 0..answers {
        offset = skip_resource(packet, offset)?;
    }

    let authorities_offset = offset;
    for _ in 0..authorities {
        offset = skip_resource(packet, offset)?;
    }

    let additionals_offset = offset;
    for _ in 0..additionals {
        offset = skip_resource(packet, offset)?;
    }

    Ok((
        Sections {
            questions,
            questions_offset,
            answers,
            answers_offset,
            authorities,
            authorities_offset,
            additionals,
            additionals_offset,
        },
        offset,
    ))
}

#[derive(Clone, PartialEq, Hash)]
pub struct NameVisitor<'a> {
    packet: &'a [u8],
    offset: usize,
}

impl<'a> NameVisitor<'a> {
    pub fn segments(&self) -> impl Iterator<Item = Result<&'_ [u8], Error>> + '_ {
        let mut offset = self.offset;
        let mut ptr_count = 0;

        std::iter::from_fn(move || {
            fn try_load_segment<'a>(
                packet: &'a [u8],
                offset: &mut usize,
                ptr_count: &mut usize,
            ) -> Result<Option<&'a [u8]>, Error> {
                loop {
                    let len_or_ptr = load_bytes::<1>(packet, *offset, None)?[0];
                    match len_or_ptr & 0b1100_0000 {
                        0b1100_0000 => {
                            if *ptr_count > 10 {
                                return Err(Error::TooManyPointers);
                            }

                            *ptr_count += 1;
                            *offset = ((len_or_ptr & 0b0011_1111) as usize) << 8
                                | (load_bytes::<1>(packet, *offset + 1, None)?[0] as usize);
                        }
                        0b0000_0000 => {
                            if len_or_ptr == 0 {
                                break Ok(None);
                            }

                            *offset += 1;

                            if packet.len() < *offset + len_or_ptr as usize {
                                return Err(Error::ShortBuffer);
                            }

                            let ret = &packet[*offset..*offset + len_or_ptr as usize];

                            *offset = *offset + len_or_ptr as usize;

                            break Ok(Some(ret));
                        }
                        _ => {
                            return Err(Error::InvalidNameSegmentBody);
                        }
                    }
                }
            }

            try_load_segment(self.packet, &mut offset, &mut ptr_count).transpose()
        })
    }
}

impl TryInto<String> for &'_ NameVisitor<'_> {
    type Error = Error;

    fn try_into(self) -> Result<String, Self::Error> {
        let mut s = String::with_capacity(48);

        for segment in self.segments() {
            let segment = segment?;
            if segment.contains(&b'.') {
                return Err(Error::InvalidNameSegmentBody);
            }

            s.push_str(std::str::from_utf8(segment).map_err(|_| Error::InvalidNameSegmentBody)?);
            s.push('.');
        }

        if s.is_empty() {
            s.push('.');
        }

        Ok(s)
    }
}

impl TryInto<String> for NameVisitor<'_> {
    type Error = Error;

    fn try_into(self) -> Result<String, Self::Error> {
        (&self).try_into()
    }
}

impl Debug for NameVisitor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.try_into().map(Cow::Owned).unwrap_or(Cow::Borrowed("<invalid>"));

        f.debug_struct("Name").field("s", &s).field("offset", &self.offset).finish()
    }
}

pub struct Packet<B> {
    packet: B,
    sections: Sections,
}

impl<B> Deref for Packet<B> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

impl<B> Packet<B> {
    pub fn new(packet: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let packet_buf = packet.as_ref();

        let (sections, offset) = collect_sections(packet_buf.as_ref())?;
        if packet_buf.len() > offset {
            return Err(Error::PacketSizeMismatch);
        }

        Ok(Self { packet, sections })
    }

    pub fn into_inner(self) -> B {
        self.packet
    }
}

fn parse_question(packet: &[u8], mut offset: usize) -> Result<(Question<NameVisitor>, usize), Error> {
    let name = NameVisitor { packet, offset };
    offset = skip_name(packet, offset)?;

    let typ = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let class = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    Ok((
        Question {
            name,
            typ: MaybeUnknown::from(typ),
            class: MaybeUnknown::from(class),
        },
        offset,
    ))
}

fn parse_resource_data(
    packet: &[u8],
    mut offset: usize,
    limit: usize,
    typ: MaybeUnknown<Type>,
) -> Result<ResourceData<NameVisitor, &[u8]>, Error> {
    let data = match typ {
        MaybeUnknown::Known(Type::A) => ResourceData::A {
            a: Ipv4Addr::from(load_bytes::<4>(packet, offset, Some(limit))?),
        },
        MaybeUnknown::Known(Type::NS) => ResourceData::NS {
            ns: NameVisitor { packet, offset },
        },
        MaybeUnknown::Known(Type::CNAME) => ResourceData::CNAME {
            cname: NameVisitor { packet, offset },
        },
        MaybeUnknown::Known(Type::SOA) => {
            let ns = NameVisitor { packet, offset };
            offset = skip_name(packet, offset)?;

            let mbox = NameVisitor { packet, offset };
            offset = skip_name(packet, offset)?;

            let serial = u32::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 4;

            let refresh = u32::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 4;

            let retry = u32::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 4;

            let expire = u32::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 4;

            let min_ttl = u32::from_be_bytes(load_bytes(packet, offset, Some(limit))?);

            ResourceData::SOA {
                ns,
                mbox,
                serial,
                refresh,
                retry,
                expire,
                min_ttl,
            }
        }
        MaybeUnknown::Known(Type::PTR) => ResourceData::PTR {
            ptr: NameVisitor { packet, offset },
        },
        MaybeUnknown::Known(Type::MX) => {
            let preference = u16::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 2;

            let mx = NameVisitor { packet, offset };

            ResourceData::MX { preference, mx }
        }
        MaybeUnknown::Known(Type::TXT) => {
            let mut texts = Vec::new();

            while offset < limit {
                let len = load_bytes::<1>(packet, offset, Some(limit))?[0] as usize;
                offset += 1;

                if offset + len > packet.len() {
                    return Err(Error::ShortBuffer);
                } else if offset + len > limit {
                    return Err(Error::PacketSizeMismatch);
                }

                texts.push(&packet[offset..offset + len]);
                offset += len;
            }

            ResourceData::TXT { txt: texts }
        }
        MaybeUnknown::Known(Type::AAAA) => ResourceData::AAAA {
            aaaa: Ipv6Addr::from(load_bytes::<16>(packet, offset, Some(limit))?),
        },
        MaybeUnknown::Known(Type::SRV) => {
            let priority = u16::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 2;

            let weight = u16::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 2;

            let port = u16::from_be_bytes(load_bytes(packet, offset, Some(limit))?);
            offset += 2;

            let target = NameVisitor { packet, offset };

            ResourceData::SRV {
                priority,
                weight,
                port,
                target,
            }
        }
        typ => ResourceData::Unknown {
            typ,
            data: &packet[offset..limit],
        },
    };

    Ok(data)
}

fn parse_resource(packet: &[u8], mut offset: usize) -> Result<(Resource<NameVisitor, &[u8]>, usize), Error> {
    let name = NameVisitor { packet, offset };
    offset = skip_name(packet, offset)?;

    let typ = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let class = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let ttl = u32::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 4;

    let data_len = u16::from_be_bytes(load_bytes(packet, offset, None)?);
    offset += 2;

    let data = parse_resource_data(packet, offset, offset + data_len as usize, MaybeUnknown::from(typ))?;
    offset += data_len as usize;

    Ok((
        Resource {
            name,
            class: MaybeUnknown::from(class),
            ttl,
            data,
        },
        offset,
    ))
}

impl<B: AsRef<[u8]>> Packet<B> {
    pub fn header(&self) -> Result<Header, Error> {
        let packet = self.packet.as_ref();

        let id = u16::from_be_bytes(load_bytes(packet, 0, None)?);
        let bits = u16::from_be_bytes(load_bytes(packet, 2, None)?);

        Ok(Header {
            id,
            resp: bits & 0b1000_0000 != 0,
            opcode: (bits & 0b0111_0000) >> 3,
            rcode: MaybeUnknown::from(bits & 0b0000_1111),
            flags: HeaderFlags::from_bits_truncate(bits),
        })
    }

    pub fn questions_len(&self) -> u16 {
        self.sections.questions
    }

    pub fn answers_len(&self) -> u16 {
        self.sections.answers
    }

    pub fn authorities_len(&self) -> u16 {
        self.sections.authorities
    }

    pub fn additionals_len(&self) -> u16 {
        self.sections.additionals
    }

    pub fn questions(&self) -> impl Iterator<Item = Result<Question<NameVisitor<'_>>, Error>> + '_ {
        let packet = self.packet.as_ref();

        let mut offset = self.sections.questions_offset;
        (0..self.sections.questions).map(move |_| {
            let (question, next_offset) = parse_question(packet, offset)?;
            offset = next_offset;

            Ok(question)
        })
    }

    fn resources(
        &self,
        mut offset: usize,
        count: u16,
    ) -> impl Iterator<Item = Result<Resource<NameVisitor<'_>, &'_ [u8]>, Error>> + '_ {
        let packet = self.packet.as_ref();

        (0..count).map(move |_| {
            let (res, next_offset) = parse_resource(packet, offset)?;
            offset = next_offset;

            Ok(res)
        })
    }

    pub fn answers(&self) -> impl Iterator<Item = Result<Resource<NameVisitor<'_>, &'_ [u8]>, Error>> + '_ {
        self.resources(self.sections.answers_offset, self.sections.answers)
    }

    pub fn authorities(&self) -> impl Iterator<Item = Result<Resource<NameVisitor<'_>, &'_ [u8]>, Error>> + '_ {
        self.resources(self.sections.authorities_offset, self.sections.authorities)
    }

    pub fn additionals(&self) -> impl Iterator<Item = Result<Resource<NameVisitor<'_>, &'_ [u8]>, Error>> + '_ {
        self.resources(self.sections.additionals_offset, self.sections.additionals)
    }
}

struct Cursor {
    offset: usize,
    count: u16,
    pos: Option<usize>,
}

impl Cursor {
    fn next(&mut self, skip: impl FnOnce(usize) -> Result<usize, Error>) -> Result<bool, Error> {
        if self.count == 0 {
            return Ok(false);
        }

        let pos = match self.pos {
            None => self.offset,
            Some(prev_pos) => skip(prev_pos)?,
        };

        self.count -= 1;

        self.pos = Some(pos);

        Ok(true)
    }

    fn pos(&self) -> Result<usize, Error> {
        self.pos.ok_or(Error::InvalidCursorState)
    }
}

pub struct QuestionsCursor<'a> {
    packet: &'a mut [u8],
    cursor: Cursor,
}

impl<'a> QuestionsCursor<'a> {
    pub fn next(&mut self) -> Result<bool, Error> {
        self.cursor.next(|offset| skip_question(self.packet, offset))
    }

    pub fn question(&self) -> Result<Question<NameVisitor>, Error> {
        let (question, _) = parse_question(self.packet, self.cursor.pos()?)?;

        Ok(question)
    }

    pub fn set_type(&mut self, typ: MaybeUnknown<Type>) -> Result<(), Error> {
        let offset = skip_name(self.packet, self.cursor.pos()?)?;

        store_bytes(self.packet, offset, typ.into().to_be_bytes())?;

        Ok(())
    }

    pub fn set_class(&mut self, class: MaybeUnknown<Class>) -> Result<(), Error> {
        let offset = skip_name(self.packet, self.cursor.pos()?)? + 2;

        store_bytes(self.packet, offset, class.into().to_be_bytes())?;

        Ok(())
    }
}

pub struct ResourcesCursor<'a> {
    packet: &'a mut [u8],
    cursor: Cursor,
}

impl<'a> ResourcesCursor<'a> {
    pub fn next(&mut self) -> Result<bool, Error> {
        self.cursor.next(|offset| skip_resource(self.packet, offset))
    }

    pub fn resource(&self) -> Result<Resource<NameVisitor, &'_ [u8]>, Error> {
        let (resource, _) = parse_resource(self.packet, self.cursor.pos()?)?;

        Ok(resource)
    }

    pub fn set_class(&mut self, class: MaybeUnknown<Class>) -> Result<(), Error> {
        let mut offset = skip_name(self.packet, self.cursor.pos()?)?;
        offset += 2; // Type

        store_bytes(self.packet, offset, class.into().to_be_bytes())?;

        Ok(())
    }

    pub fn set_ttl(&mut self, ttl: u32) -> Result<(), Error> {
        let mut offset = skip_name(self.packet, self.cursor.pos()?)?;
        offset += 2; // Type
        offset += 2; // Class

        store_bytes(self.packet, offset, ttl.to_be_bytes())?;

        Ok(())
    }
}

impl<B: AsMut<[u8]>> Packet<B> {
    pub fn set_header(&mut self, header: Header) -> Result<(), Error> {
        let id = header.id;
        let bits = (header.flags & HeaderFlags::all()).bits() | (header.opcode & 0b111) << 3 | (header.rcode.into() & 0b1111);

        let packet = self.packet.as_mut();
        store_bytes(packet, 0, id.to_be_bytes())?;
        store_bytes(packet, 2, bits.to_be_bytes())?;
        Ok(())
    }

    pub fn questions_cursor(&mut self) -> QuestionsCursor<'_> {
        QuestionsCursor {
            packet: self.packet.as_mut(),
            cursor: Cursor {
                offset: self.sections.questions_offset,
                count: self.sections.questions,
                pos: None,
            },
        }
    }

    fn resources_cursor(&mut self, offset: usize, count: u16) -> ResourcesCursor<'_> {
        ResourcesCursor {
            packet: self.packet.as_mut(),
            cursor: Cursor {
                offset,
                count,
                pos: None,
            },
        }
    }

    pub fn answers_cursor(&mut self) -> ResourcesCursor<'_> {
        self.resources_cursor(self.sections.answers_offset, self.sections.answers)
    }

    pub fn authorities_cursor(&mut self) -> ResourcesCursor<'_> {
        self.resources_cursor(self.sections.authorities_offset, self.sections.authorities)
    }

    pub fn additionals_cursor(&mut self) -> ResourcesCursor<'_> {
        self.resources_cursor(self.sections.additionals_offset, self.sections.additionals)
    }
}
