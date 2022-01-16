extern crate nom;

use std::io;
use std::env;
use std::fmt;
use std::fmt::Display;
use std::fs;
use std::net::UdpSocket;
use std::str;
use std::str::FromStr;

use nom::{
    IResult,
    bits::{bits, streaming::take},
    branch::alt,
    character::{is_alphabetic, is_digit},
    character::complete::line_ending,
    combinator::{map, map_res, verify, peek},
    error::Error,
    sequence::{delimited, terminated, preceded, tuple},
    character::complete::char,
    bytes::complete::{tag, take_while_m_n, take_while},
    multi::{many0, many1, length_count, length_data},
    number::complete::{be_u16, be_u8, be_i32, be_u32, be_u128},
};

// Notes:
// ------
//
// This is only a POC.
//
// The work is based on several RFCs and the IANA site.
// While it implements more than RFC-1035, e.g. AAAA. Those,
// are implemented only on a best-effort basis.
//
// It supports only RFC-1035 label types. So, normal ones and pointers.
// It does not yet support underscores for non-hostname labels.
//
// It does not support several important RRs, e.g. OPT, DNSSEC.

// ---------------------------------------
// Start of hex string parsing
// ---------------------------------------

fn from_hex(input: &str) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(input, 16)
}

fn is_hex_digit(c: char) -> bool {
    c.is_digit(16)
}

fn hex_tag(input: &str) -> IResult<&str, u8> {
    preceded(
        tag("\\x"),
        map_res(
            take_while_m_n(2, 2, is_hex_digit),
            from_hex
        )
    ) (input)
}

fn hex_line(input: &str) -> IResult<&str, Vec<u8>> {
    delimited(
        char('\"'),
        many1(hex_tag),
        char('\"')
    ) (input)
}

fn parse_hex_message(input: &str) -> IResult<&str, Vec<u8>> {
    // Intermediate lines
    let (input, mut res1) = many0(
        terminated(
            hex_line,
            tuple((
                tag(" \\"),
                line_ending,
            ))
        )
    ) (input)?;
    // Last line
    let (input, mut res2) = hex_line(input)?;
    // Flatten and collect the results
    let mut ret = Vec::new();
    for v in &mut res1 {
        ret.append(v);
    }
    ret.append(&mut res2);
    Ok((input, ret))
}

// ---------------------------------------
// End of hex string parsing
// ---------------------------------------

// ---------------------------------------
// DNS Header
// ---------------------------------------

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[repr(u8)]
enum DNSMessageQR {
    Query = 0,
    Response = 1,
}

impl DNSMessageQR {
    fn from_u8(n: u8) -> Option<DNSMessageQR> {
        match n {
            0 => Some(DNSMessageQR::Query),
            1 => Some(DNSMessageQR::Response),
            _ => None,
        }
    }

    /// true -> Query
    /// false -> Response
    fn from_bool(q: bool) -> DNSMessageQR {
        if q {
            DNSMessageQR::Query
        } else {
            DNSMessageQR::Response
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum DNSMessageOpCode {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    DSO,
    Other(u8),
}

impl DNSMessageOpCode {
    fn from_u8(n: u8) -> DNSMessageOpCode {
        match n {
            0 => DNSMessageOpCode::Query,
            1 => DNSMessageOpCode::IQuery,
            2 => DNSMessageOpCode::Status,
            4 => DNSMessageOpCode::Notify,
            5 => DNSMessageOpCode::Update,
            6 => DNSMessageOpCode::DSO,
            n => DNSMessageOpCode::Other(n),
        }
    }
}

impl Display for DNSMessageOpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSMessageOpCode::Query => write!(f, "QUERY"),
            DNSMessageOpCode::IQuery => write!(f, "IQUERY"),
            DNSMessageOpCode::Status => write!(f, "STATUS"),
            DNSMessageOpCode::Notify => write!(f, "NOTIFY"),
            DNSMessageOpCode::Update => write!(f, "UPDATE"),
            DNSMessageOpCode::DSO => write!(f, "DSO"),
            DNSMessageOpCode::Other(n) => write!(f, "OPCODE{}", n),
        }
    }
}

/// Based on RFC-1035 and RFC-6895, although the latter is not fully implemented.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum DNSMessageRCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    DSOTYPENI,
    BADSIG,
    BADKEY,
    BADTIME,
    BADMODE,
    BADNAME,
    BADALG,
    BADTRUNC,
    BADCOOKIE,
    Other(u8),
}

impl DNSMessageRCode {
    fn from_u8(n: u8) -> DNSMessageRCode {
        match n {
            0 => DNSMessageRCode::NoError,
            1 => DNSMessageRCode::FormErr,
            2 => DNSMessageRCode::ServFail,
            3 => DNSMessageRCode::NXDomain,
            4 => DNSMessageRCode::NotImp,
            5 => DNSMessageRCode::Refused,
            6 => DNSMessageRCode::YXDomain,
            7 => DNSMessageRCode::YXRRSet,
            8 => DNSMessageRCode::NXRRSet,
            9 => DNSMessageRCode::NotAuth,
            10 => DNSMessageRCode::NotZone,
            11 => DNSMessageRCode::DSOTYPENI,
            16 => DNSMessageRCode::BADSIG,
            17 => DNSMessageRCode::BADKEY,
            18 => DNSMessageRCode::BADTIME,
            19 => DNSMessageRCode::BADMODE,
            20 => DNSMessageRCode::BADNAME,
            21 => DNSMessageRCode::BADALG,
            22 => DNSMessageRCode::BADTRUNC,
            23 => DNSMessageRCode::BADCOOKIE,
            n => DNSMessageRCode::Other(n),
        }
    }
}

impl Display for DNSMessageRCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSMessageRCode::NoError => write!(f, "NOERROR"),
            DNSMessageRCode::FormErr => write!(f, "FORMERR"),
            DNSMessageRCode::ServFail => write!(f, "SERVFAIL"),
            DNSMessageRCode::NXDomain => write!(f, "NXDOMAIN"),
            DNSMessageRCode::NotImp => write!(f, "NOTIMP"),
            DNSMessageRCode::Refused => write!(f, "REFUSED"),
            DNSMessageRCode::YXDomain => write!(f, "YXDOMAIN"),
            DNSMessageRCode::YXRRSet => write!(f, "YXRRSET"),
            DNSMessageRCode::NXRRSet => write!(f, "NXRRSET"),
            DNSMessageRCode::NotAuth => write!(f, "NOTAUTH"),
            DNSMessageRCode::NotZone => write!(f, "NOTZONE"),
            DNSMessageRCode::DSOTYPENI => write!(f, "DSOTYPENI"),
            DNSMessageRCode::BADSIG => write!(f, "BADSIG"),
            DNSMessageRCode::BADKEY => write!(f, "BADKEY"),
            DNSMessageRCode::BADTIME => write!(f, "BADTIME"),
            DNSMessageRCode::BADMODE => write!(f, "BADMODE"),
            DNSMessageRCode::BADNAME => write!(f, "BADNAME"),
            DNSMessageRCode::BADALG => write!(f, "BADALG"),
            DNSMessageRCode::BADTRUNC => write!(f, "BADTRUNC"),
            DNSMessageRCode::BADCOOKIE => write!(f, "BADCOOKIE"),
            DNSMessageRCode::Other(n) => write!(f, "RCODE{}", n),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DNSMessageHeader {
    id : u16,
    qr : DNSMessageQR,
    op_code : DNSMessageOpCode,
    aa : bool,
    tc : bool,
    rd : bool,
    ra : bool,
    ad : bool,
    cd : bool,
    r_code : DNSMessageRCode,
    qd_count : u16,
    an_count : u16,
    ns_count : u16,
    ar_count : u16,
}

impl Display for DNSMessageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            ";; ->>HEADER<<- opcode: {}, status: {}, id: {}\n;; flags:",
            self.op_code,
            self.r_code,
            self.id,
        )?;
        if self.qr == DNSMessageQR::Response {
            write!(f, " qr")?;
        }
        if self.aa {
            write!(f, " aa")?;
        }
        if self.tc {
            write!(f, " tc")?;
        }
        if self.rd {
            write!(f, " rd")?;
        }
        if self.ra {
            write!(f, " ra")?;
        }
        if self.ad {
            write!(f, " ad")?;
        }
        if self.cd {
            write!(f, " cd")?;
        }
        write!(f, "; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n", self.qd_count, self.an_count, self.ns_count, self.ar_count)
    }
}

fn parse_header_bits(input: &[u8]) -> IResult<&[u8], (DNSMessageQR, DNSMessageOpCode, bool, bool, bool, bool, bool, bool, DNSMessageRCode)> {
    bits::<_, _, Error<(&[u8], usize)>, _, _>(
        tuple((
            take(1usize),
            take(4usize),
            take(1usize),
            take(1usize),
            take(1usize),
            take(1usize),
            verify(take(1usize), |res: &u8| *res == 0), // Reserved 1 bit
            take(1usize),
            take(1usize),
            take(4usize),
        ))
    ) (input)
        .map(
            |(rest, res): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8)) | (rest, (
                DNSMessageQR::from_bool(res.0 == 0),
                DNSMessageOpCode::from_u8(res.1),
                res.2 == 1,
                res.3 == 1,
                res.4 == 1,
                res.5 == 1,
                res.7 == 1,
                res.8 == 1,
                DNSMessageRCode::from_u8(res.9),
            ))
        )
}

fn parse_header(input: &[u8]) -> IResult<&[u8], DNSMessageHeader> {
    tuple((
        be_u16,
        parse_header_bits,
        be_u16,
        be_u16,
        be_u16,
        be_u16,
    )) (input)
        .map(
            |(rest, res)| (rest, DNSMessageHeader {
                id: res.0,
                qr: res.1.0,
                op_code: res.1.1,
                aa: res.1.2,
                tc: res.1.3,
                rd: res.1.4,
                ra: res.1.5,
                ad: res.1.6,
                cd: res.1.7,
                r_code: res.1.8,
                qd_count: res.2,
                an_count: res.3,
                ns_count: res.4,
                ar_count: res.5,
            })
        )
}

// ---------------------------------------
// End of DNS Header
// ---------------------------------------

// ---------------------------------------
// Start of Label Handling
// ---------------------------------------

/// Label Table. Helps in dereferencing label pointers.
/// It uses a "sparse" vector internally.
///
/// This is a helper struct. The user is responsible for ensuring its consistency.
/// As long as it is populated from a real message and in order, it will be consistent.
///
/// Idea: Store all labels in order in a Vec<((usize, usize), String)>. The tuple's
/// first element (pos, size) stores the original position and size of the domain in the message.
/// The second element stores the fully expanded domain.
/// No need to do multiple hops over pointers to expand a label fully.
///
/// The search algorithm is sequential. While a binary search would be better theoretically,
/// I think the sequential search is perfect for such a small data.
#[derive(Debug, Clone)]
struct LabelTable {
    labels: Vec<((usize, usize), String)>,
}

impl LabelTable {
    fn new() -> LabelTable {
        LabelTable {
            labels: vec![]
        }
    }

    /// position: byte position in message
    /// size: byte size in message (can be smaller than domain's size)
    /// domain: the full domain
    fn add_label(&mut self, position: usize, size: usize, domain: &str) -> &str {
        self.labels.push(((position, size), domain.to_string()));
        &self.labels.last().unwrap().1
    }

    fn get_label(&self, position: usize) -> Option<&str> {
        if self.labels.len() == 0 {
            return None;
        }
        let mut index : usize = 0;
        let mut cursor = self.labels.first().unwrap();
        if position < cursor.0.0 {
            return None;
        }
        while position >= (cursor.0.0 + cursor.0.1) {
            cursor = match self.labels.get(index + 1) {
                Some(c) => c,
                _ => {
                    return None;
                }
            };
            index += 1;
        }
        if position < cursor.0.0 {
            // hole
            return None;
        }
        if position == cursor.0.0 {
            return Some(&cursor.1);
        }
        if cursor.1.as_bytes()[position - cursor.0.0 - 1] == b'.' {
            return Some(cursor.1.split_at(position - cursor.0.0).1);
        }
        None
    }
}

#[test]
fn test_label_table() {
    let mut table = LabelTable::new();
    table.add_label(30, 8, "bla.net.");
    table.add_label(60, 4, "put.bla.net.");
    table.add_label(90, 14, "f.put.bla.net.");
    println!("LabelTable: {:?}\n", table);
    assert_eq!(table.get_label(29), None);
    assert_eq!(table.get_label(30), Some("bla.net."));
    assert_eq!(table.get_label(31), None);
    assert_eq!(table.get_label(34), Some("net."));
    assert_eq!(table.get_label(45), None);
    assert_eq!(table.get_label(60), Some("put.bla.net."));
    assert_eq!(table.get_label(61), None);
    assert_eq!(table.get_label(64), None); // No "bla.net.", as that pointer would be invalid.
    assert_eq!(table.get_label(90), Some("f.put.bla.net."));
    assert_eq!(table.get_label(92), Some("put.bla.net."));
}

fn is_correct_inner_label_char(c: u8) -> bool {
    is_alphabetic(c) || (c == b'-') || is_digit(c)
}

fn is_correct_ending_label_char(c: u8) -> bool {
    is_alphabetic(c) || is_digit(c)
}

fn parse_label<'a>(input: &'a [u8], size: usize, name: &mut String) -> Result<&'a [u8], &'static str> {
    if input.len() < size {
        return Err("Input length and label size mismatch");
    }
    match size {
        1 => {
            if is_alphabetic(input[0]) {
                name.push(char::from(input[0]));
                Ok(input.get(1..).unwrap())
            } else {
                Err("Wrong label character")
            }
        },
        2 => {
            if is_alphabetic(input[0]) || is_correct_ending_label_char(input[1]) {
                name.push_str(str::from_utf8(&input[0..2]).unwrap());
                Ok(input.get(2..).unwrap())
            } else {
                Err("Wrong label character")
            }
        },
        _ => {
            if !is_alphabetic(input[0]) {
                return Err("Wrong label character");
            }
            for i in 1..(size - 2) {
                if !is_correct_inner_label_char(input[i]) {
                    return Err("Wrong label character");
                }
            }
            if is_correct_ending_label_char(input[size - 1]) {
                name.push_str(str::from_utf8(&input[0..size]).unwrap());
                return Ok(input.get(size..).unwrap());
            } else {
                return Err("Wrong label character");
            }
        }
    }
}

#[test]
fn test_label_parsing() {
    let buf = &[b'p', b'8', b'd', b'p', b'-', b'p'];
    let mut name = String::new();
    let mut ret = parse_label(buf, 3, &mut name);
    assert_eq!(name, "p8d");
    assert_eq!(ret, Ok(&[b'p', b'-', b'p'][..]));
    ret = parse_label(ret.unwrap(), 3, &mut name);
    println!("Name: {}\n", name);
    assert_eq!(name, "p8dp-p");
    assert_eq!(ret, Ok(&[][..]));
    let wrong_buf_1 = &[b'7', b'o', b'p'];
    ret = parse_label(wrong_buf_1, 3, &mut name);
    assert_eq!(ret, Err("Wrong label character"));
    let wrong_buf_2 = &[b'p', b'o', b'-'];
    ret = parse_label(wrong_buf_1, 3, &mut name);
    assert_eq!(ret, Err("Wrong label character"));
    assert_eq!(name, "p8dp-p");
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum LabelType {
    Normal(usize),
    Pointer(usize),
    End,
    Other,
}

fn peek_label_type(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
    peek(bits::<_, _, Error<(&[u8], usize)>, _, _>(
        tuple((
            take(1usize),
            take(1usize),
        ))
    )) (input)
}

fn parse_label_type(input: &[u8]) -> IResult<&[u8], LabelType> {
    match peek_label_type(input) {
        Ok((_, (1u8, 1u8))) => {
            bits::<_, _, Error<(&[u8], usize)>, _, _>(
                tuple((
                    take(1usize),
                    take(1usize),
                    take(6usize),
                    take(8usize),
                ))
            ) (input).map(| (input, (_, _, left, right)): (&[u8], (u8, u8, u8, u8)) | {
                (input, LabelType::Pointer((((left as u16) << 8) | right as u16) as usize))
            })
        },
        Ok((_, (0u8, 0u8))) => {
            bits::<_, _, Error<(&[u8], usize)>, _, _>(
                tuple((
                    take(1usize),
                    take(1usize),
                    take(6usize),
                ))
            ) (input).map(| (input, (_, _, size)): (&[u8], (u8, u8, u8)) | {
                if size == 0 {
                    return (input, LabelType::End);
                } else {
                    return (input, LabelType::Normal(size as usize));
                }
            })
        },
        _ => Ok((input, LabelType::Other)),
    }
}

fn parse_name<'a, 'b>(s: &'a [u8], label_table: &'b mut LabelTable, msg_position: usize) -> Result<(&'a [u8], (&'b str, usize)), &'static str> {
    let mut total_size = 0usize;
    let mut name = String::new();
    let mut input = s;
    loop {
        match parse_label_type(input) {
            Ok((inner_input, label_type)) => {
                match label_type {
                    LabelType::Normal(size) => {
                        if name.len() > 0 {
                            name.push('.');
                        }
                        total_size += 1 + size;
                        input = parse_label(inner_input, size, &mut name)?;
                    },
                    LabelType::Pointer(position) => {
                        total_size += 2;
                        if name.len() > 0 {
                            name.push('.');
                        }
                        let label = match label_table.get_label(position) {
                            Some(label) => label,
                            _ => {
                                return Err("Failed to parse name");
                            },
                        };
                        name.push_str(label);
                        let n = label_table.add_label(msg_position, total_size, &name);
                        return Ok((inner_input, (n, total_size)));
                    },
                    LabelType::End => {
                        total_size += 1;
                        name.push('.');
                        let n = label_table.add_label(msg_position, total_size, &name);
                        return Ok((inner_input, (n, total_size)));
                    },
                    LabelType::Other => {
                        return Err("Failed to parse name");
                    }
                }
            },
            _ => {
                return Err("Failed to parse name");
            },
        }
    }
}

#[test]
fn test_full_label_parsing() {
    let mut table = LabelTable::new();
    let input = [0b00000001u8, 0b01000001u8, 0b00000000u8]; // A.
    let mut result = parse_name(&input, &mut table, 10);
    assert_eq!(result, Ok((&[][..], ("A.", 3))));
    assert_eq!(table.get_label(10), Some("A."));
    let input_p = [0b11000000u8, 0b00001010u8]; // Pointer to 10
    result = parse_name(&input_p, &mut table, 20);
    assert_eq!(result, Ok((&[][..], ("A.", 2))));
    assert_eq!(table.get_label(20), Some("A."));
}

// ---------------------------------------
// End of Label Handling
// ---------------------------------------

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum DNSClass {
    In,
    CS,
    Chaos,
    Hesiod,
    QCLASS_NONE,
    QCLASS_ANY,
    Other(u16),
}

impl DNSClass {
    fn from_u16(n: u16) -> DNSClass {
        match n {
            1 => DNSClass::In,
            2 => DNSClass::CS,
            3 => DNSClass::Chaos,
            4 => DNSClass::Hesiod,
            254 => DNSClass::QCLASS_NONE,
            255 => DNSClass::QCLASS_ANY,
            n => DNSClass::Other(n),
        }
    }
}

impl Display for DNSClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSClass::In => write!(f, "IN"),
            DNSClass::CS => write!(f, "CS"),
            DNSClass::Chaos => write!(f, "CHAOS"),
            DNSClass::Hesiod => write!(f, "HESIOD"),
            DNSClass::QCLASS_NONE => write!(f, "NONE"),
            DNSClass::QCLASS_ANY => write!(f, "ANY"),
            DNSClass::Other(n) => write!(f, "CLASS{}", n),
        }
    }
}

// ---------------------------------------
// Start of Query Section
// ---------------------------------------

#[derive(Debug, Clone)]
struct DNSQDSectionEntry {
    qname: String,
    qtype: DNSRRType,
    qclass: DNSClass,
    size: usize,
}

impl DNSQDSectionEntry {
    fn new(qname: String, qtype: u16, qclass: u16, size: usize) -> DNSQDSectionEntry {
        DNSQDSectionEntry {
            qname: qname,
            qtype: DNSRRType::from_u16(qtype),
            qclass: DNSClass::from_u16(qclass),
            size: size,
        }
    }
}

impl Display for DNSQDSectionEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, ";{}\t\t{}\t{}\n", self.qname, self.qclass, self.qtype)
    }
}

fn parse_qtype_qclass(input: &[u8]) -> IResult<&[u8], (u16, u16)> {
    tuple((
        be_u16,
        be_u16,
    )) (input)
}

fn parse_qd_entry<'a>(input: &'a [u8], label_table: &mut LabelTable, msg_position: usize) -> Result<(&'a [u8], DNSQDSectionEntry), &'static str>  {
    let name_res = parse_name(input, label_table, msg_position)?;
    match parse_qtype_qclass(name_res.0) {
        Ok((input, (t, c))) => {
            Ok((input, DNSQDSectionEntry::new(name_res.1.0.to_string(), t, c, 4 + name_res.1.1)))
        },
        _ => Err("Failed to parse QDEntry")
    }
}

fn parse_qd_section<'a>(input: &'a [u8], label_table: &mut LabelTable, qd_position: usize, count: u16) -> Result<(&'a [u8], Vec<DNSQDSectionEntry>, usize), &'static str> {
    let mut qd_vec = vec![];
    let mut pos = qd_position;
    let mut input = input;
    for _ in 0..count {
        let result = parse_qd_entry(input, label_table, pos)?;
        input = result.0;
        pos += result.1.size;
        qd_vec.push(result.1);
    }
    Ok((input, qd_vec, pos))
}

// ---------------------------------------
// End of Query Section
// ---------------------------------------

// ---------------------------------------
// Start of Resource Records
// ---------------------------------------

fn is_ascii_printable(c: u8) -> bool {
    c.is_ascii_graphic() || ( c == b' ')
}

fn parse_printable_char_string(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    length_count(
        be_u8,
        map(take_while_m_n(1, 1, is_ascii_printable), | res: &[u8]| res[0])
    ) (input)
}

fn parse_binary_char_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(be_u8) (input)
}

#[test]
fn test_parse_char_string() {
    use nom::error::ErrorKind::TakeWhileMN;
    let input = [0b00000100u8, b'h', b'i', b'!', b'!'];
    let result = parse_printable_char_string(&input);
    assert_eq!(result, Ok((&[][..], vec![b'h', b'i', b'!', b'!'])));
    let wrong_input = [0b00000101u8, b'h', b'i', b'!', b'!', 0b11000000u8];
    let result = parse_printable_char_string(&wrong_input);
    assert_eq!(result, Err(nom::Err::Error(Error { input: &[192u8][..], code: TakeWhileMN })));
    let result = parse_binary_char_string(&wrong_input);
    assert_eq!(result, Ok((&[][..], &[b'h', b'i', b'!', b'!', 0b11000000u8][..])));
    let short_input = [0b00000101u8, 0b11000000u8];
    let result = parse_binary_char_string(&short_input);
    assert_eq!(result, Err(nom::Err::Incomplete(nom::Needed::new(4))));
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum DNSRRType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    RP,
    AFSDB,
    X25,
    ISDN,
    RT,
    NSAP,
    NSAPPTR,
    SIG,
    KEY,
    PX,
    GPOS,
    AAAA,
    LOC,
    NXT,
    EID,
    NIMLOC,
    SRV,
    ATMA,
    NAPTR,
    KX,
    CERT,
    A6,
    DNAME,
    SINK,
    OPT,
    APL,
    DS,
    SSHFP,
    IPSECKEY,
    RRSIG,
    NSEC,
    DNSKEY,
    DHCID,
    NSEC3,
    NSEC3PARAM,
    TLSA,
    SMIMEA,
    HIP,
    NINFO,
    RKEY,
    TALINK,
    CDS,
    CDNSKEY,
    OPENPGPKEY,
    CSYNC,
    ZONEMD,
    SVCB,
    HTTPS,
    SPF,
    UINFO,
    UID,
    GID,
    UNSPEC,
    NID,
    L32,
    L64,
    LP,
    EUI48,
    EUI64,
    TKEY,
    TSIG,
    IXFR,
    AXFR,
    MAILB,
    MAILA,
    ANY,
    URI,
    CAA,
    AVC,
    DOA,
    AMTRELAY,
    TA,
    DLV,
    Other(u16),
}

impl DNSRRType {
    fn from_u16(n: u16) -> DNSRRType {
        match n {
            1 => DNSRRType::A,
            2 => DNSRRType::NS,
            3 => DNSRRType::MD,
            4 => DNSRRType::MF,
            5 => DNSRRType::CNAME,
            6 => DNSRRType::SOA,
            7 => DNSRRType::MB,
            8 => DNSRRType::MG,
            9 => DNSRRType::MR,
            10 => DNSRRType::NULL,
            11 => DNSRRType::WKS,
            12 => DNSRRType::PTR,
            13 => DNSRRType::HINFO,
            14 => DNSRRType::MINFO,
            15 => DNSRRType::MX,
            16 => DNSRRType::TXT,
            17 => DNSRRType::RP,
            18 => DNSRRType::AFSDB,
            19 => DNSRRType::X25,
            20 => DNSRRType::ISDN,
            21 => DNSRRType::RT,
            22 => DNSRRType::NSAP,
            23 => DNSRRType::NSAPPTR,
            24 => DNSRRType::SIG,
            25 => DNSRRType::KEY,
            26 => DNSRRType::PX,
            27 => DNSRRType::GPOS,
            28 => DNSRRType::AAAA,
            29 => DNSRRType::LOC,
            30 => DNSRRType::NXT,
            31 => DNSRRType::EID,
            32 => DNSRRType::NIMLOC,
            33 => DNSRRType::SRV,
            34 => DNSRRType::ATMA,
            35 => DNSRRType::NAPTR,
            36 => DNSRRType::KX,
            37 => DNSRRType::CERT,
            38 => DNSRRType::A6,
            39 => DNSRRType::DNAME,
            40 => DNSRRType::SINK,
            41 => DNSRRType::OPT,
            42 => DNSRRType::APL,
            43 => DNSRRType::DS,
            44 => DNSRRType::SSHFP,
            45 => DNSRRType::IPSECKEY,
            46 => DNSRRType::RRSIG,
            47 => DNSRRType::NSEC,
            48 => DNSRRType::DNSKEY,
            49 => DNSRRType::DHCID,
            50 => DNSRRType::NSEC3,
            51 => DNSRRType::NSEC3PARAM,
            52 => DNSRRType::TLSA,
            53 => DNSRRType::SMIMEA,
            // hole
            55 => DNSRRType::HIP,
            56 => DNSRRType::NINFO,
            57 => DNSRRType::RKEY,
            58 => DNSRRType::TALINK,
            59 => DNSRRType::CDS,
            60 => DNSRRType::CDNSKEY,
            61 => DNSRRType::OPENPGPKEY,
            62 => DNSRRType::CSYNC,
            63 => DNSRRType::ZONEMD,
            64 => DNSRRType::SVCB,
            65 => DNSRRType::HTTPS,
            99 => DNSRRType::SPF,
            100 => DNSRRType::UINFO,
            101 => DNSRRType::UID,
            102 => DNSRRType::GID,
            103 => DNSRRType::UNSPEC,
            104 => DNSRRType::NID,
            105 => DNSRRType::L32,
            106 => DNSRRType::L64,
            107 => DNSRRType::LP,
            108 => DNSRRType::EUI48,
            109 => DNSRRType::EUI64,
            249 => DNSRRType::TKEY,
            250 => DNSRRType::TSIG,
            251 => DNSRRType::IXFR,
            252 => DNSRRType::AXFR,
            253 => DNSRRType::MAILB,
            254 => DNSRRType::MAILA,
            255 => DNSRRType::ANY,
            256 => DNSRRType::URI,
            257 => DNSRRType::CAA,
            258 => DNSRRType::AVC,
            259 => DNSRRType::DOA,
            260 => DNSRRType::AMTRELAY,
            32768 => DNSRRType::TA,
            32769 => DNSRRType::DLV,
            n => DNSRRType::Other(n),
        }
    }
}

impl Display for DNSRRType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSRRType::A => write!(f, "A"),
            DNSRRType::NS => write!(f, "NS"),
            DNSRRType::MD => write!(f, "MD"),
            DNSRRType::MF => write!(f, "MF"),
            DNSRRType::CNAME => write!(f, "CNAME"),
            DNSRRType::SOA => write!(f, "SOA"),
            DNSRRType::MB => write!(f, "MB"),
            DNSRRType::MG => write!(f, "MG"),
            DNSRRType::MR => write!(f, "MR"),
            DNSRRType::NULL => write!(f, "NULL"),
            DNSRRType::WKS => write!(f, "WKS"),
            DNSRRType::PTR => write!(f, "PTR"),
            DNSRRType::HINFO => write!(f, "HINFO"),
            DNSRRType::MINFO => write!(f, "MINFO"),
            DNSRRType::MX => write!(f, "MX"),
            DNSRRType::TXT => write!(f, "TXT"),
            DNSRRType::RP => write!(f, "RP"),
            DNSRRType::AFSDB => write!(f, "AFSDB"),
            DNSRRType::X25 => write!(f, "X25"),
            DNSRRType::ISDN => write!(f, "ISDN"),
            DNSRRType::RT => write!(f, "RT"),
            DNSRRType::NSAP => write!(f, "NSAP"),
            DNSRRType::NSAPPTR => write!(f, "NSAPPTR"),
            DNSRRType::SIG => write!(f, "SIG"),
            DNSRRType::KEY => write!(f, "KEY"),
            DNSRRType::PX => write!(f, "PX"),
            DNSRRType::GPOS => write!(f, "GPOS"),
            DNSRRType::AAAA => write!(f, "AAAA"),
            DNSRRType::LOC => write!(f, "LOC"),
            DNSRRType::NXT => write!(f, "NXT"),
            DNSRRType::EID => write!(f, "EID"),
            DNSRRType::NIMLOC => write!(f, "NIMLOC"),
            DNSRRType::SRV => write!(f, "SRV"),
            DNSRRType::ATMA => write!(f, "ATMA"),
            DNSRRType::NAPTR => write!(f, "NAPTR"),
            DNSRRType::KX => write!(f, "KX"),
            DNSRRType::CERT => write!(f, "CERT"),
            DNSRRType::A6 => write!(f, "A6"),
            DNSRRType::DNAME => write!(f, "DNAME"),
            DNSRRType::SINK => write!(f, "SINK"),
            DNSRRType::OPT => write!(f, "OPT"),
            DNSRRType::APL => write!(f, "APL"),
            DNSRRType::DS => write!(f, "DS"),
            DNSRRType::SSHFP => write!(f, "SSHFP"),
            DNSRRType::IPSECKEY => write!(f, "IPSECKEY"),
            DNSRRType::RRSIG => write!(f, "RRSIG"),
            DNSRRType::NSEC => write!(f, "NSEC"),
            DNSRRType::DNSKEY => write!(f, "DNSKEY"),
            DNSRRType::DHCID => write!(f, "DHCID"),
            DNSRRType::NSEC3 => write!(f, "NSEC3"),
            DNSRRType::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            DNSRRType::TLSA => write!(f, "TLSA"),
            DNSRRType::SMIMEA => write!(f, "SMIMEA"),
            DNSRRType::HIP => write!(f, "HIP"),
            DNSRRType::NINFO => write!(f, "NINFO"),
            DNSRRType::RKEY => write!(f, "RKEY"),
            DNSRRType::TALINK => write!(f, "TALINK"),
            DNSRRType::CDS => write!(f, "CDS"),
            DNSRRType::CDNSKEY => write!(f, "CDNSKEY"),
            DNSRRType::OPENPGPKEY => write!(f, "OPENPGPKEY"),
            DNSRRType::CSYNC => write!(f, "CSYNC"),
            DNSRRType::ZONEMD => write!(f, "ZONEMD"),
            DNSRRType::SVCB => write!(f, "SVCB"),
            DNSRRType::HTTPS => write!(f, "HTTPS"),
            DNSRRType::SPF => write!(f, "SPF"),
            DNSRRType::UINFO => write!(f, "UINFO"),
            DNSRRType::UID => write!(f, "UID"),
            DNSRRType::GID => write!(f, "GID"),
            DNSRRType::UNSPEC => write!(f, "UNSPEC"),
            DNSRRType::NID => write!(f, "NID"),
            DNSRRType::L32 => write!(f, "L32"),
            DNSRRType::L64 => write!(f, "L64"),
            DNSRRType::LP => write!(f, "LP"),
            DNSRRType::EUI48 => write!(f, "EUI48"),
            DNSRRType::EUI64 => write!(f, "EUI64"),
            DNSRRType::TKEY => write!(f, "TKEY"),
            DNSRRType::TSIG => write!(f, "TSIG"),
            DNSRRType::IXFR => write!(f, "IXFR"),
            DNSRRType::AXFR => write!(f, "AXFR"),
            DNSRRType::MAILB => write!(f, "MAILB"),
            DNSRRType::MAILA => write!(f, "MAILA"),
            DNSRRType::ANY => write!(f, "ANY"),
            DNSRRType::URI => write!(f, "URI"),
            DNSRRType::CAA => write!(f, "CAA"),
            DNSRRType::AVC => write!(f, "AVC"),
            DNSRRType::DOA => write!(f, "DOA"),
            DNSRRType::AMTRELAY => write!(f, "AMTRELAY"),
            DNSRRType::TA => write!(f, "TA"),
            DNSRRType::DLV => write!(f, "DLV"),
            DNSRRType::Other(n) => write!(f, "TYPE{}", n),
        }
    }
}

#[derive(Debug, Clone)]
struct DNSRRHead {
    qname: String,
    rr_type: DNSRRType,
    rr_class: DNSClass,
    ttl: i32,
    rd_length: u16,
    size: usize,
}

impl DNSRRHead {
    fn new(qname: String, rr_type: u16, rr_class: u16, ttl: i32, rd_length: u16, size: usize) -> DNSRRHead {
        DNSRRHead {
            qname: qname,
            rr_type: DNSRRType::from_u16(rr_type),
            rr_class: DNSClass::from_u16(rr_class),
            ttl: ttl,
            rd_length: rd_length,
            size: size,
        }
    }
}

fn parse_rr_fixed(input: &[u8]) -> IResult<&[u8], (u16, u16, i32, u16)> {
    tuple((
        be_u16,
        be_u16,
        be_i32,
        be_u16,
    )) (input)
}

fn parse_rr_head<'a>(input: &'a [u8], label_table: &mut LabelTable, position: usize) -> Result<(&'a [u8], DNSRRHead), &'static str>  {
    let name_res = parse_name(input, label_table, position)?;
    match parse_rr_fixed(name_res.0) {
        Ok((input, (t, c, ttl, rdlen))) => {
            Ok((input, DNSRRHead::new(name_res.1.0.to_string(), t, c, ttl, rdlen, 10 + name_res.1.1)))
        },
        _ => Err("Failed to parse RR")
    }
}

#[derive(Debug, Clone)]
enum DNSParsedRDATA {
    A(u32),
    AAAA(u128),
    CNAME(String),
    HINFO(Vec<u8>, Vec<u8>),
    MX(u16, String),
    NS(String),
    PTR(String),
    SOA(String, String, u32, i32, i32, i32, i32),
    TXT(Vec<Vec<u8>>),
    Other(DNSRRType, Vec<u8>),
}

fn format_rr(f: &mut fmt::Formatter<'_>, head: &DNSRRHead, rdata: &DNSParsedRDATA) -> fmt::Result {
    write!(f, "{}\t\t{}\t{}\t{}\t", head.qname, head.ttl, head.rr_class, head.rr_type)?;
    match rdata {
        DNSParsedRDATA::A(ip) => {
            let ipb = ip.to_be_bytes();
            write!(f, "{}.{}.{}.{}\n", ipb[0], ipb[1], ipb[2], ipb[3])
        },
        DNSParsedRDATA::AAAA(ip) => {
            let ipb = ip.to_be_bytes();
            write!(
                f,
                "{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}\n",
                ipb[0], ipb[1], ipb[2], ipb[3],
                ipb[4], ipb[5], ipb[6], ipb[7],
                ipb[8], ipb[9], ipb[10], ipb[11],
                ipb[12], ipb[13], ipb[14], ipb[15],
            )
        },
        DNSParsedRDATA::CNAME(name) => {
            write!(f, "{}\n", name)
        },
        DNSParsedRDATA::HINFO(cpu, os) => {
            write!(f, "\\# ")?;
            for i in &*cpu {
                write!(f, "{:02X}", i)?;
            }
            write!(f, "\n\\# ")?;
            for i in &*os {
                write!(f, "{:02X}", i)?;
            }
            write!(f, "\n")
        },
        DNSParsedRDATA::MX(n, name) => {
            write!(f, "{} {}\n", n, name)
        },
        DNSParsedRDATA::NS(name) => {
            write!(f, "{}\n", name)
        },
        DNSParsedRDATA::PTR(name) => {
            write!(f, "{}\n", name)
        },
        DNSParsedRDATA::SOA(mname, rname, serial, refresh, retry, expire, minimum) => {
            write!(
                f,
                "{} {} {} {} {} {} {}\n",
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            )
        },
        DNSParsedRDATA::TXT(txt) => {
            for i in &*txt {
                let mut printable = true;
                for j in &*i {
                    if !is_ascii_printable(*j) {
                        printable = false;
                        break;
                    }
                }
                if printable {
                    write!(f, "\"")?;
                    for j in &*i {
                        write!(f, "{}", char::from(*j))?;
                    }
                    write!(f, "\"\n")?;
                } else {
                    write!(f, "\\# ")?;
                    for j in &*i {
                        write!(f, "{:02X}", j)?;
                    }
                    write!(f, "\n")?;
                }
            }
            Ok(())
        },
        DNSParsedRDATA::Other(_rr_type, data) => {
            write!(f, "\\# ")?;
            for i in &*data {
                write!(f, "{:02X}", i)?;
            }
            write!(f, "\n")
        },
    }
}

fn parse_rr_rdata<'a>(input: &'a [u8], label_table: &mut LabelTable, position: usize, rr_head: &DNSRRHead) -> Result<(&'a [u8], DNSParsedRDATA), &'static str>  {
    match (rr_head.rr_class, rr_head.rr_type) {
        (_, DNSRRType::CNAME) => parse_rr_cname(input, label_table, position),
        (_, DNSRRType::HINFO) => parse_rr_hinfo(input),
        (_, DNSRRType::MX) => parse_rr_mx(input, label_table, position),
        (_, DNSRRType::NS) => parse_rr_ns(input, label_table, position),
        (_, DNSRRType::PTR) => parse_rr_ptr(input, label_table, position),
        (_, DNSRRType::SOA) => parse_rr_soa(input, label_table, position),
        (_, DNSRRType::TXT) => parse_rr_txt(input, rr_head.rd_length.into()),
        (DNSClass::In, DNSRRType::A) => parse_rr_a(input),
        (DNSClass::In, DNSRRType::AAAA) => parse_rr_aaaa(input),
        (_, _) => {
            let slen: usize = rr_head.rd_length.into();
            let rdata = &input[0..slen];
            Ok((&input[slen..], DNSParsedRDATA::Other(rr_head.rr_type, rdata.to_vec())))
        },
    }
}

fn parse_rr_cname<'a>(input: &'a [u8], label_table: &mut LabelTable, position: usize) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    let name_res = parse_name(input, label_table, position)?;
    Ok((name_res.0, DNSParsedRDATA::CNAME(name_res.1.0.to_string())))
}

fn parse_rr_hinfo_helper(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    tuple((
        parse_binary_char_string,
        parse_binary_char_string,
    )) (input)
}

fn parse_rr_hinfo<'a>(input: &'a [u8]) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    match parse_rr_hinfo_helper(input) {
        Ok((input, (cpu, os))) => Ok((input, DNSParsedRDATA::HINFO(cpu.to_vec(), os.to_vec()))),
        _ => Err("Failed to parse.")
    }
}

fn parse_rr_mx_helper(input: &[u8]) -> IResult<&[u8], u16> {
    be_u16(input)
}

fn parse_rr_mx<'a>(input: &'a [u8], label_table: &mut LabelTable, position: usize) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    match parse_rr_mx_helper(input) {
        Ok((input, preference)) => {
            let name_res = parse_name(input, label_table, 2 + position)?;
            Ok((name_res.0, DNSParsedRDATA::MX(preference, name_res.1.0.to_string())))
        },
        _ => Err("Failed to parse.")
    }
}

fn parse_rr_ns<'a>(input: &'a [u8], label_table: &mut LabelTable, position: usize) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    let name_res = parse_name(input, label_table, position)?;
    Ok((name_res.0, DNSParsedRDATA::NS(name_res.1.0.to_string())))
}

fn parse_rr_ptr<'a>(input: &'a [u8], label_table: &mut LabelTable, position: usize) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    let name_res = parse_name(input, label_table, position)?;
    Ok((name_res.0, DNSParsedRDATA::PTR(name_res.1.0.to_string())))
}

fn parse_rr_soa_helper(input: &[u8]) -> IResult<&[u8], (u32, i32, i32, i32, i32)> {
    tuple((
        be_u32,
        be_i32,
        be_i32,
        be_i32,
        be_i32,
    )) (input)
}

fn parse_rr_soa<'a>(input: &'a [u8], label_table: &mut LabelTable, position: usize) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    let mname_res = parse_name(input, label_table, position)?;
    let mname_size: usize = mname_res.1.1;
    let mname = mname_res.1.0.to_string();
    let rname_res = parse_name(mname_res.0, label_table, position + mname_size)?;
    match parse_rr_soa_helper(rname_res.0) {
        Ok((input, (serial, refresh, retry, expire, minimum))) => Ok((
            input,
            DNSParsedRDATA::SOA(
                mname,
                rname_res.1.0.to_string(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            ))),
        _ => Err("Failed to parse.")
    }
}

fn parse_rr_txt_helper(input: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    many1(parse_binary_char_string)(input)
}

fn parse_rr_txt<'a>(input: &'a [u8], rd_length: usize) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    match parse_rr_txt_helper(&input[0..rd_length]) {
        Ok((input, records)) => {
            let mut ret = Vec::new();
            for v in records {
                ret.push(v.to_vec());
            }
            Ok((input, DNSParsedRDATA::TXT(ret)))
        }
        _ => Err("Failed to parse.")
    }
}

fn parse_rr_a_helper(input: &[u8]) -> IResult<&[u8], u32> {
    be_u32 (input)
}

fn parse_rr_a<'a>(input: &'a [u8]) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    match parse_rr_a_helper(input) {
        Ok((input, ip)) => Ok((input, DNSParsedRDATA::A(ip))),
        _ => Err("Failed to parse.")
    }
}

fn parse_rr_aaaa_helper(input: &[u8]) -> IResult<&[u8], u128> {
    be_u128 (input)
}

fn parse_rr_aaaa<'a>(input: &'a [u8]) -> Result<(&'a [u8], DNSParsedRDATA), &'static str> {
    match parse_rr_aaaa_helper(input) {
        Ok((input, ip)) => Ok((input, DNSParsedRDATA::AAAA(ip))),
        _ => Err("Failed to parse.")
    }
}

// ---------------------------------------
// End of Resource Records
// ---------------------------------------

#[derive(Debug, Clone)]
struct DNSMessage {
    header : DNSMessageHeader,
    label_table : LabelTable,
    qd : Vec<DNSQDSectionEntry>,
    an : Vec<(DNSRRHead, DNSParsedRDATA)>,
    ns : Vec<(DNSRRHead, DNSParsedRDATA)>,
    ar : Vec<(DNSRRHead, DNSParsedRDATA)>,
}

// Header size: 12

impl DNSMessage {
    fn new(header: DNSMessageHeader) -> DNSMessage {
        DNSMessage {
            header: header,
            label_table: LabelTable::new(),
            qd: vec![],
            an: vec![],
            ns: vec![],
            ar: vec![],
        }
    }
}

impl Display for DNSMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n", self.header)?;
        if self.qd.len() > 0 {
            write!(f, ";; QUESTION SECTION:\n")?;
            for qde in &self.qd {
                write!(f, "{}\n", qde)?;
            }
        }
        if self.an.len() > 0 {
            write!(f, ";; ANSWER SECTION:\n")?;
            for ane in &self.an {
                format_rr(f, &ane.0, &ane.1)?;
            }
        }
        if self.ns.len() > 0 {
            write!(f, ";; AUTHORITY SECTION:\n")?;
            for nse in &self.ns {
                format_rr(f, &nse.0, &nse.1)?;
            }
        }
        if self.ar.len() > 0 {
            write!(f, ";; ADDITIONAL SECTION:\n")?;
            for are in &self.ar {
                format_rr(f, &are.0, &are.1)?;
            }
        }
        Ok(())
    }
}

fn parse_dns_message<'a>(input: &'a [u8]) -> Result<(&'a [u8], DNSMessage), &'static str> {
    let (source, header) = match parse_header(input) {
        Ok((s, h)) => (s, h),
        Err(_) => {
            return Err("Failed to parse message.");
        }
    };
    let mut message = DNSMessage::new(header);
    let (mut source, qd, mut pos) = parse_qd_section(source, &mut message.label_table, 12, header.qd_count)?;
    message.qd = qd;
    for _ in 0..header.an_count {
        let (input, rr_head) = parse_rr_head(source, &mut message.label_table, pos)?;
        pos += rr_head.size;
        let (input, rr_data) = parse_rr_rdata(input, &mut message.label_table,  pos, &rr_head)?;
        pos += rr_head.rd_length as usize;
        message.an.push((rr_head, rr_data));
        source = input;
    }
    for _ in 0..header.ns_count {
        let (input, rr_head) = parse_rr_head(source, &mut message.label_table, pos)?;
        pos += rr_head.size;
        let (input, rr_data) = parse_rr_rdata(input, &mut message.label_table,  pos, &rr_head)?;
        pos += rr_head.rd_length as usize;
        message.ns.push((rr_head, rr_data));
        source = input;
    }
    for _ in 0..header.ar_count {
        let (input, rr_head) = parse_rr_head(source, &mut message.label_table, pos)?;
        pos += rr_head.size;
        let (input, rr_data) = parse_rr_rdata(input, &mut message.label_table,  pos, &rr_head)?;
        pos += rr_head.rd_length as usize;
        message.ar.push((rr_head, rr_data));
        source = input;
    }
    Ok((source, message))
}


fn main() -> io::Result<()> {
    // dig @1.1.1.1 A www.kpn.com
    let id = 52749u16;
    let query_flags = 0b0_0000_0010_000_0000u16;
    let counts = [0u8, 1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
    // let qname = [0b00000011u8, b'w', b'w', b'w', 0b00000011u8, b'k', b'p', b'n', 0b00000011u8, b'c', b'o', b'm', 0b00000000u8];
    let qname = [0b00000011u8, b'k', b'p', b'n', 0b00000011u8, b'c', b'o', b'm', 0b00000000u8];
    // let qname = [0b00001010u8, b'q', b'u', b'a', b't', b'e', b'r', b'n', b'i', b'o', b'n', 0b00000101u8, b's', b'p', b'a', b'c', b'e', 0b00000000u8];
    let qtype = 48u16;
    let qclass = 1u16;
    let mut query_msg = vec![];
    query_msg.extend_from_slice(&id.to_be_bytes());
    query_msg.extend_from_slice(&query_flags.to_be_bytes());
    query_msg.extend_from_slice(&counts);
    query_msg.extend_from_slice(&qname);
    query_msg.extend_from_slice(&qtype.to_be_bytes());
    query_msg.extend_from_slice(&qclass.to_be_bytes());
    let socket = UdpSocket::bind("0.0.0.0:34254").expect("Failed to open UDP connection.");
    socket.connect(("1.1.1.1", 53)).expect("Failed to connect to server.");
    socket.send(&query_msg).expect("Failed to send query to server.");
    let mut buf = [0; 512];
    let input = match socket.recv(&mut buf) {
        Ok(received) => {
            // println!("received {} bytes {:?}\n", received, &buf[..received]);
            &buf[..received]
        },
        Err(_e) => {
            // println!("recv function failed: {:?}\n", e);
            return Ok(());
        },
    };
    match parse_dns_message(input) {
        Ok((_rest, message)) => {
            println!("{}", message);
            Ok(())
        },
        Err(err) => {
            println!("err:{:?}\n", err);
            Ok(())
        },
    }
}
