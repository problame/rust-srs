
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
}

#[derive(Debug,Clone)]
pub struct SRS0Address {
    pub hash: String,
    pub tt: String,
    pub hostname: String,
    pub local: String,
    pub domain: String,
    pub separator: String,
}

#[derive(Debug,Clone)]
pub struct SRS1Address {
    pub hash: String,
    pub hostname: String,
    pub opaque_local: String,
    pub domain: String,
    pub separator: String,
}

struct SRSParser<'a> {
    input: &'a str,
}

#[derive(Clone,Copy,Debug)]
pub enum Err {
    SRSPrefixError,
    SRS0FormatError,
    SRS1FormatError,
    EmptyRemainingAddress,
    NoDomainInAddress,
}

type SRSParserResult = Result<SRSAddress, Err>;

impl<'a> SRSParser<'a> {

    fn new(input: &str) -> SRSParser {
        return SRSParser{
            input: input,
        };
    }

    fn parse_srs0(&mut self, separator: &'a str) -> SRSParserResult {

        use self::Err::*;

        let mut idx = 5;

        let mut comps = Vec::with_capacity(3);
        for _ in 0..3 {
            if let Some(pos) = self.input[idx..].find(separator) {
                comps.push(&self.input[idx..idx+pos]);
                idx += pos + 1; // Skip it
            } else {
                return Err(SRS0FormatError);
            }
        }
        assert!(comps.len() == 3);

        let hash = comps[0];
        let tt = comps[1];
        let hostname = comps[2];

        if idx >= self.input.len() {
            return Err(EmptyRemainingAddress);
        }

        let ld_sep_pos = match self.input[idx..].find("@") {
            Some(x) => x,
            None    => return Err(NoDomainInAddress),
        };

        let local = &self.input[idx..idx+ld_sep_pos];
        let domain = &self.input[idx+ld_sep_pos+1..];

        // TODO could go with zero-copy
        return Ok(SRS0(SRS0Address{
            separator: separator.to_string(),
            hash: hash.to_string(),
            tt: tt.to_string(),
            hostname: hostname.to_string(),
            local: local.to_string(),
            domain: domain.to_string(),
        }));
    }

    fn parse_srs1(&mut self, separator: &'a str) -> SRSParserResult {

        use self::Err::*;

        let mut idx = 5;

        let mut comps = Vec::with_capacity(2);

        for _ in 0..2 {
            if let Some(pos) = self.input[idx..].find(separator) {
                comps.push(&self.input[idx..idx+pos]);
                idx += pos + 1; // Skip separator
            } else {
                return Err(SRS1FormatError);
            }
        }
        assert!(comps.len() == 2);

        let hash = comps[0];
        let hostname = comps[1];

        let ld_sep_pos = match self.input[idx..].find("@") {
            Some(x) => x,
            None    => return Err(NoDomainInAddress),
        };

        let opaque_local = &self.input[idx..idx+ld_sep_pos];
        let domain = &self.input[idx+ld_sep_pos+1..];

        // TODO do zero-copy here
        return Ok (SRS1(SRS1Address{
            separator: separator.to_string(),
            hash: hash.to_string(),
            hostname: hostname.to_string(),
            opaque_local: opaque_local.to_string(),
            domain: domain.to_string(),
        }));

    }

    fn parse(&mut self) -> SRSParserResult {

        if self.input.len() < 5 {
            return Err(Err::SRSPrefixError);
        }

        let version = match &self.input[0..4] {
            "SRS0" => 0,
            "SRS1" => 1,
            _      => return Err(Err::SRSPrefixError),
        };

        let separator = &self.input[4..5];

        return match version {
            0 => self.parse_srs0(separator),
            1 => self.parse_srs1(separator),
            _ => panic!("variable should not contain a value != 0 or 1"),
        };
    }
}

impl SRSAddress {

    pub fn from_string(s: &str) -> SRSParserResult {
        let mut p = SRSParser::new(s);
        return p.parse();
    }

}

