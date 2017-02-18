mod tests;
mod tokenizer;
mod tokenizer_tests;

use std::collections::VecDeque;

const SRS_SEPARATOR: &'static str = "=";
const LOCAL_DOMAIN_SEPARATOR: &'static str = "@";

use self::SRSAddress::*;

#[derive(Debug)]
enum SRSAddress<'a> {
    SRS0(SRS0Address<'a>),
    SRS1(SRS1Address<'a>),
}

impl<'a> SRSAddress<'a> {
    fn get_version(&self) -> u8 {
        match self {
            &SRS0(_) => 0,
            &SRS1(_) => 1,
        }
    }
    fn is_0(&self) -> bool { return self.get_version() == 0; }
    fn is_1(&self) -> bool { return self.get_version() == 1; }
    fn SRS0(self) -> SRS0Address<'a> { 
        match self {
            SRS0(srs) => srs,
            _         => panic!("not an SRS0"),
        }
    }
    fn SRS1(self) -> SRS1Address<'a> { 
        match self {
            SRS1(srs) => srs,
            _         => panic!("not an SRS1"),
        }
    }

}

#[derive(Debug)]
struct SRS0Address<'a> {
    hash: &'a str,
    tt: &'a str,
    hostname: &'a str,
    local: &'a str,
    domain: &'a str,
}

#[derive(Debug)]
struct SRS1Address<'a> {
    hash: &'a str,
    hostname: &'a str,
    // opaque local
    // domain
    // TODO: cannot parse the above because the parse_srs1 routine
    //       cannot say 'and now everything until the LOCAL_DOMAIN_SEPARATOR'
}

struct SRSParser<'a> {
    split: VecDeque<&'a str>,
}

#[derive(Clone,Copy,Debug)]
enum Err {
    SRSPrefixError,
    ExpectedNonemptyToken,
    ExpectedEmptyToken,
    ExpectedNoMoreTokens,
}

type SRSParserResult<'a> = Result<SRSAddress<'a>, Err>;

impl<'a> SRSParser<'a> {

    fn new(input: &str) -> SRSParser {
        // Split the input in srs@domain part
        let mut at_split = input.split(LOCAL_DOMAIN_SEPARATOR);
        // Tokenize by SRS_SEPARATOR
        let srs_split =
            at_split.next()
            .map(|s| s.split(SRS_SEPARATOR))
            .expect("a mail address must have a local part");
        let tokens = srs_split.chain(at_split).collect();

        let x: SRSParser = SRSParser{
            split: tokens,
        };
        return x;
    }

    fn expect_srs_prefix(&mut self) -> Result<u8, Err> {
        let err = Err::SRSPrefixError;
        return self.split.pop_front()
            .ok_or(err)
            .and_then(|p| {
                if p.len() != 4 {
                    return Err(err);
                }

                let (pre, suff) = p.split_at(3);
                if pre != "SRS" {
                    return Err(err);
                }

                let srs_version_num: Result<u8, _> = suff.parse();
                return match srs_version_num {
                    Ok(0) | Ok(1) => Ok(srs_version_num.unwrap()),
                    _     => Err(err),
                };
            });
    }

    fn expect_finished(&mut self) -> Result<(), Err> {
        match self.split.pop_front() {
            None => Ok(()),
            _    => Err(Err::ExpectedNoMoreTokens),
        }
    }

    fn expect_nonempty(&mut self) -> Result<&'a str,Err> {
        let err = Err::ExpectedNonemptyToken;
        self.split.pop_front()
            .ok_or(err)
            .and_then(|x| {
                match x.len() {
                    0 => Err(err),
                    _ => Ok(x),
                }
            })
    }

    fn expect_empty(&mut self) -> Result<(), Err> {
        let err = Err::ExpectedEmptyToken;
        self.split.pop_front()
            .ok_or(err)
            .and_then(|x| {
                match x.len() {
                    0 => Ok(()),
                    _ => Err(err),
                }
            })
    }

    fn parse_srs0(&mut self) -> SRSParserResult<'a> {

        let hash = self.expect_nonempty();
        if let Err(x) = hash { return Err(x) }
        let tt = self.expect_nonempty();
        if let Err(x) = tt { return Err(x) }
        let hostname = self.expect_nonempty();
        if let Err(x) = hostname { return Err(x) }
        let local = self.expect_nonempty();
        if let Err(x) = local { return Err(x) }
        let domain = self.expect_nonempty();
        if let Err(x) = domain { return Err(x) }

        if let Err(x) = self.expect_finished() {
            return Err(x);
        }

        return Ok(SRS0(SRS0Address{
            hash: hash.unwrap(),
            tt: tt.unwrap(),
            hostname: hostname.unwrap(),
            local: local.unwrap(),
            domain: domain.unwrap(),
        }));
    }

    fn parse_srs1(&mut self) -> SRSParserResult<'a> {

        let hash = self.expect_nonempty();
        if let Err(x) = hash { return Err(x) }
        let hostname = self.expect_nonempty();
        if let Err(x) = hostname { return Err(x) }

        if let Err(x) = self.expect_empty() {
            return Err(x);
        }

        return Ok (SRS1(SRS1Address{
            hash: hash.unwrap(),
            hostname: hostname.unwrap(),
        }));
    }

    fn parse(&mut self) -> SRSParserResult<'a> {
        return match self.expect_srs_prefix() {
            Err(x) => return Err(x),
            Ok(0)  => return self.parse_srs0(),
            Ok(1)  => return self.parse_srs1(),
            Ok(_)  => panic!("this should have been checked before"),
        }
    }
}

impl<'a> SRSAddress<'a> {

    fn from_string(s: &str) -> SRSParserResult {
        let mut p = SRSParser::new(s);
        return p.parse();
    }

}

