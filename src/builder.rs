use std::{
    collections::BTreeMap,
    io::{Seek, SeekFrom, Write},
    marker::PhantomData,
};

use crate::{Error, Header, HeaderFlags, MaybeUnknown, Question, Resource, ResourceData, Type};

pub struct WantsHeader;
pub struct WantsQuestions;
pub struct WantsAnswers;
pub struct WantsAuthorities;
pub struct WantsAdditionals;

pub struct Builder<W: Write + Seek, P> {
    writer: W,
    begin_pos: u64,
    name_ptrs: BTreeMap<Vec<u8>, u16>,
    questions: u16,
    answers: u16,
    authorities: u16,
    additionals: u16,
    _phase: PhantomData<P>,
}

impl<W: Write + Seek, P> Builder<W, P> {
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write + Seek, P> Builder<W, P> {
    #[inline]
    fn move_to_next_phase<NP>(self) -> Builder<W, NP> {
        Builder {
            writer: self.writer,
            begin_pos: self.begin_pos,
            name_ptrs: self.name_ptrs,
            questions: self.questions,
            answers: self.answers,
            authorities: self.authorities,
            additionals: self.additionals,
            _phase: PhantomData,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.writer.write_all(bytes)?;
        Ok(())
    }

    fn write_at(&mut self, pos: u64, bytes: &[u8]) -> Result<(), Error> {
        let current = self.writer.stream_position()?;
        self.writer.seek(SeekFrom::Start(pos))?;
        self.writer.write_all(bytes)?;
        self.writer.seek(SeekFrom::Start(current))?;
        Ok(())
    }

    fn pack_name(&mut self, name: &str) -> Result<(), Error> {
        if name == "." {
            return Ok(self.write(&[0])?);
        }

        let name = name.as_bytes();
        if name.last().copied() != Some(b'.') {
            return Err(Error::NonCanonicalName);
        }

        let dot_indexes = name
            .iter()
            .enumerate()
            .filter_map(|(idx, c)| if *c == b'.' { Some(idx) } else { None });

        let mut segment_begin_index = 0usize;
        for segment_end_index in dot_indexes {
            let segment_len = segment_end_index - segment_begin_index;
            if segment_len == 0 || segment_len >= 1 << 6 {
                return Err(Error::InvalidNameSegmentSize(segment_len));
            }

            if let Some(ptr) = self.name_ptrs.get(&name[segment_begin_index..]) {
                self.write(&(*ptr | 0xc000).to_be_bytes())?;

                return Ok(());
            }

            let new_ptr = self.writer.stream_position()? - self.begin_pos;
            if new_ptr <= (u16::MAX >> 2) as u64 {
                self.name_ptrs.insert(name[segment_begin_index..].to_vec(), new_ptr as u16);
            }

            self.write(&[segment_len as u8])?;
            self.write(&name[segment_begin_index..segment_end_index])?;

            segment_begin_index = segment_end_index + 1;
        }

        self.write(&[0])?;

        Ok(())
    }

    fn pack_question<N: AsRef<str>>(&mut self, question: &Question<N>) -> Result<(), Error> {
        self.pack_name(question.name.as_ref())?;
        self.write(&question.typ.into().to_be_bytes())?;
        self.write(&question.class.into().to_be_bytes())?;

        Ok(())
    }

    fn pack_resource<N: AsRef<str>, D: AsRef<[u8]>>(&mut self, resource: &Resource<N, D>) -> Result<(), Error> {
        let typ = match &resource.data {
            ResourceData::CNAME { .. } => MaybeUnknown::Known(Type::CNAME),
            ResourceData::MX { .. } => MaybeUnknown::Known(Type::MX),
            ResourceData::NS { .. } => MaybeUnknown::Known(Type::NS),
            ResourceData::PTR { .. } => MaybeUnknown::Known(Type::PTR),
            ResourceData::SOA { .. } => MaybeUnknown::Known(Type::SOA),
            ResourceData::TXT { .. } => MaybeUnknown::Known(Type::TXT),
            ResourceData::SRV { .. } => MaybeUnknown::Known(Type::SRV),
            ResourceData::A { .. } => MaybeUnknown::Known(Type::A),
            ResourceData::AAAA { .. } => MaybeUnknown::Known(Type::AAAA),
            ResourceData::Unknown { typ, .. } => *typ,
        };

        self.pack_name(resource.name.as_ref())?;
        self.write(&typ.into().to_be_bytes())?;
        self.write(&resource.class.into().to_be_bytes())?;
        self.write(&resource.ttl.to_be_bytes())?;

        let len_pos = self.writer.stream_position()?;
        self.write(&0u16.to_be_bytes())?;

        match &resource.data {
            ResourceData::CNAME { cname } => {
                self.pack_name(cname.as_ref())?;
            }
            ResourceData::MX { preference, mx } => {
                self.write(&preference.to_be_bytes())?;
                self.pack_name(mx.as_ref())?;
            }
            ResourceData::NS { ns } => {
                self.pack_name(ns.as_ref())?;
            }
            ResourceData::PTR { ptr } => {
                self.pack_name(ptr.as_ref())?;
            }
            ResourceData::SOA {
                ns,
                mbox,
                serial,
                refresh,
                retry,
                expire,
                min_ttl,
            } => {
                self.pack_name(ns.as_ref())?;
                self.pack_name(mbox.as_ref())?;
                self.write(&serial.to_be_bytes())?;
                self.write(&refresh.to_be_bytes())?;
                self.write(&retry.to_be_bytes())?;
                self.write(&expire.to_be_bytes())?;
                self.write(&min_ttl.to_be_bytes())?;
            }
            ResourceData::TXT { txt } => {
                for txt in txt {
                    let txt = txt.as_ref();
                    if txt.len() > u8::MAX as usize {
                        return Err(Error::TextTooLong);
                    }

                    self.write(&[txt.len() as u8])?;
                    self.write(txt)?;
                }
            }
            ResourceData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                self.write(&priority.to_be_bytes())?;
                self.write(&weight.to_be_bytes())?;
                self.write(&port.to_be_bytes())?;
                self.pack_name(target.as_ref())?;
            }
            ResourceData::A { a } => {
                self.write(&a.octets())?;
            }
            ResourceData::AAAA { aaaa } => {
                self.write(&aaaa.octets())?;
            }
            ResourceData::Unknown { data, .. } => {
                self.write(data.as_ref())?;
            }
        }

        let writing_pos = self.writer.stream_position()?;
        self.writer.seek(SeekFrom::Start(len_pos))?;
        self.writer.write_all(&((writing_pos - len_pos - 2) as u16).to_be_bytes())?;
        self.writer.seek(SeekFrom::Start(writing_pos))?;

        Ok(())
    }
}

impl<W: Write + Seek> Builder<W, WantsHeader> {
    pub fn new(mut writer: W) -> Result<Self, Error> {
        let begin_pos = writer.stream_position()?;

        Ok(Self {
            writer,
            begin_pos,
            name_ptrs: BTreeMap::new(),
            questions: 0,
            answers: 0,
            authorities: 0,
            additionals: 0,
            _phase: PhantomData,
        })
    }

    pub fn write_header(mut self, header: Header) -> Result<Builder<W, WantsQuestions>, Error> {
        let id = header.id;
        let bits = (if header.resp { 1 << 15 } else { 0 })
            | (header.opcode & 0b111) << 11
            | (header.flags & HeaderFlags::all()).bits()
            | header.rcode.into() & 0b1111;

        self.write(&id.to_be_bytes())?;
        self.write(&bits.to_be_bytes())?;
        self.write(&0u16.to_be_bytes())?;
        self.write(&0u16.to_be_bytes())?;
        self.write(&0u16.to_be_bytes())?;
        self.write(&0u16.to_be_bytes())?;

        Ok(self.move_to_next_phase())
    }
}

impl<W: Write + Seek> Builder<W, WantsQuestions> {
    pub fn write_question<N: AsRef<str>>(mut self, question: &Question<N>) -> Result<Self, Error> {
        self.pack_question(question)?;

        self.questions += 1;

        Ok(self)
    }

    pub fn finish_questions(mut self) -> Result<Builder<W, WantsAnswers>, Error> {
        self.write_at(self.begin_pos + 4, &self.questions.to_be_bytes())?;

        Ok(self.move_to_next_phase())
    }
}

impl<W: Write + Seek> Builder<W, WantsAnswers> {
    pub fn write_answer<N: AsRef<str>, D: AsRef<[u8]>>(mut self, answer: &Resource<N, D>) -> Result<Self, Error> {
        self.pack_resource(answer)?;

        self.answers += 1;

        Ok(self)
    }

    pub fn finish_answers(mut self) -> Result<Builder<W, WantsAuthorities>, Error> {
        self.write_at(self.begin_pos + 6, &self.answers.to_be_bytes())?;

        Ok(self.move_to_next_phase())
    }
}

impl<W: Write + Seek> Builder<W, WantsAuthorities> {
    pub fn write_authority<N: AsRef<str>, D: AsRef<[u8]>>(mut self, authority: &Resource<N, D>) -> Result<Self, Error> {
        self.pack_resource(authority)?;

        self.authorities += 1;

        Ok(self)
    }

    pub fn finish_authorities(mut self) -> Result<Builder<W, WantsAdditionals>, Error> {
        self.write_at(self.begin_pos + 8, &self.authorities.to_be_bytes())?;

        Ok(self.move_to_next_phase())
    }
}

impl<W: Write + Seek> Builder<W, WantsAdditionals> {
    pub fn write_additional<N: AsRef<str>, D: AsRef<[u8]>>(mut self, additional: &Resource<N, D>) -> Result<Self, Error> {
        self.pack_resource(additional)?;

        self.additionals += 1;

        Ok(self)
    }

    pub fn finish_additionals(mut self) -> Result<W, Error> {
        self.write_at(self.begin_pos + 10, &self.additionals.to_be_bytes())?;

        Ok(self.writer)
    }
}
