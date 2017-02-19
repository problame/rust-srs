use std::cell::RefCell;

use srs::tokenizer::*;
use srs::tokenizer::Token::*;

const SRS_SEPARATOR: &'static str = "=";
const LOCAL_DOMAIN_SEPARATOR: &'static str = "@";

use self::SRSAddress::*;

#[derive(Debug)]
pub enum SRSAddress {
    SRS0(SRS0Address),
    SRS1(SRS1Address),
}

impl SRSAddress {
    fn get_version(&self) -> u8 {
        match self {
            &SRS0(_) => 0,
            &SRS1(_) => 1,
        }
    }
    pub fn is_0(&self) -> bool { return self.get_version() == 0; }
    pub fn is_1(&self) -> bool { return self.get_version() == 1; }
    pub fn srs0(self) -> SRS0Address {
        match self {
            SRS0(srs) => srs,
            _         => panic!("not an SRS0"),
        }
    }
    pub fn srs1(self) -> SRS1Address {
        match self {
            SRS1(srs) => srs,
            _         => panic!("not an SRS1"),
        }
    }
    pub fn get_hash(self) -> String {
        match self {
            SRS0(s) => s.hash.clone(),
            SRS1(s) => s.hash.clone(),
        }
    }
}

#[derive(Debug)]
pub struct SRS0Address {
    pub hash: String,
    pub tt: String,
    pub hostname: String,
    pub local: String,
    pub domain: String,
}

#[derive(Debug)]
pub struct SRS1Address {
    pub hash: String,
    pub hostname: String,
    pub opaque_local: String,
    pub domain: String,
}

struct SRSParser<'a> {
    tokenizer: Tokenizer<'a>
}

#[derive(Clone,Copy,Debug)]
pub enum Err {
    SRSPrefixError,
    ExpectedSRSSeparator,
    ExpectedNoMoreTokens,
    ExpectedNonemptyToken,
    ExpectedNonemptyLocalPart,
}

type SRSParserResult = Result<SRSAddress, Err>;

impl<'a> SRSParser<'a> {

    fn new(input: &str) -> SRSParser {
        let t = Tokenizer::tokenize(input, SRS_SEPARATOR, LOCAL_DOMAIN_SEPARATOR);
        return SRSParser{
            tokenizer: t,
        };
    }

    fn expect_srs_prefix(&mut self) -> Result<Token, Err> {
        let err = Err::SRSPrefixError;
        return self.tokenizer.next()
            .ok_or(err)
            .and_then(|t| {
                match t {
                    SRS(_) => Ok(t),
                    _             => Err(err),
                }
            });
    }

    fn expect_finished(&mut self) -> Result<(), Err> {
        match self.tokenizer.next() {
            None => Ok(()),
            _    => Err(Err::ExpectedNoMoreTokens),
        }
    }

    fn expect_nonempty_text(&mut self) -> Result<String,Err> {
        let err = Err::ExpectedNonemptyToken;
        self.tokenizer.next()
            .ok_or(err)
            .and_then(|x| {
                match x {
                    Text("") => Err(err),
                    Text(t)  => Ok(t.to_string()),
                    _        => Err(err),
                }
            })
    }

    fn expect_separator(&mut self, t: Token) -> Result<(), Err> {
        let err = Err::ExpectedSRSSeparator;
        self.tokenizer.next()
            .ok_or(err)
            .and_then(|x| if x == t { Ok(()) } else { Err(err) } )
    }

    fn expect_srs_separator(&mut self) -> Result<(), Err> {
        self.expect_separator(SRSSeparator)
    }

    fn parse_srs0(&mut self) -> SRSParserResult {

        try!(self.expect_srs_separator());
        let hash = try!(self.expect_nonempty_text());
        try!(self.expect_srs_separator());
        let tt = try!(self.expect_nonempty_text());
        try!(self.expect_srs_separator());
        let hostname = try!(self.expect_nonempty_text());
        try!(self.expect_srs_separator());
        let local = try!(self.expect_nonempty_text());
        try!(self.expect_separator(LocalDomainSeparator));
        let mut domain = try!(self.expect_nonempty_text());
        loop { // because a for loop would need to borrow self.tokenizer mutably...
            let t = self.tokenizer.next();
            match t {
                None => break,
                Some(t) => {
                    let ot = self.tokenizer.text_of_token(&t);
                    domain += &ot;
                }
            }
        }

        try!(self.expect_finished());

        return Ok(SRS0(SRS0Address{
            hash: hash,
            tt: tt,
            hostname: hostname,
            local: local,
            domain: domain,
        }));
    }

    fn parse_srs1(&mut self) -> SRSParserResult {

        try!(self.expect_srs_separator());
        let hash = try!(self.expect_nonempty_text());
        try!(self.expect_srs_separator());
        let hostname = try!(self.expect_nonempty_text());
        try!(self.expect_srs_separator());

        let (opaque_local, domain) = try!({ // This is ugly...
            let opaque_local = RefCell::new(String::new());
            let domain = RefCell::new(String::new());
            {
                let mut which = opaque_local.borrow_mut();
                loop {
                    let t = self.tokenizer.next();
                    match t {
                        None => break,
                        Some(LocalDomainSeparator) => {
                             which = domain.borrow_mut();
                             continue;
                        },
                        Some(token) => {
                        which.push_str(self.tokenizer.text_of_token(&token).as_str());
                        }
                    }
                }
            }

            let opaque_local = opaque_local.into_inner();
            let domain = domain.into_inner();
            match opaque_local.as_ref() {
                "" => Err(Err::ExpectedNonemptyLocalPart),
                _  => Ok((opaque_local, domain))
            }
        });

        try!(self.expect_finished());

        return Ok (SRS1(SRS1Address{
            hash: hash,
            hostname: hostname,
            opaque_local: opaque_local,
            domain: domain,
        }));
    }

    fn parse(&mut self) -> SRSParserResult {
        match self.expect_srs_prefix() {
            Err(x) => return Err(x),
            Ok(SRS(0))  => return self.parse_srs0(),
            Ok(SRS(1))  => return self.parse_srs1(),
            Ok(_)       => panic!("this should have been checked before"),
        }
    }
}

impl SRSAddress {

    pub fn from_string(s: &str) -> SRSParserResult {
        let mut p = SRSParser::new(s);
        return p.parse();
    }

}

