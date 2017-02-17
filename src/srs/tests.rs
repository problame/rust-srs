#[cfg(test)]
mod test {

    use srs::{SRSAddress,SRSParser,SRSParserResult};

    //fn new_parser_result(s: &str) -> SRSParserResult {
    //}

    #[test]
    fn it_parses_srs0() {
        let r = SRSAddress::from_string("SRS0=HHH=TT=source.com=user@forwarder=theoreticallylegit");

        assert!(r.is_ok());
        let a = r.unwrap();
        println!("{:?}", a);
        assert!(a.is_0());
        let a = match a {
            SRSAddress::SRS0(x) => x,
            _ => panic!("expected SRS0"),
        };
        assert!(a.hash == "HHH");
        assert!(a.tt == "TT");
        assert!(a.hostname == "source.com");
        assert!(a.local == "user");
        assert!(a.domain == "forwarder=theoreticallylegit");
    }

    #[test]
    fn it_parses_srs1() {
        let r = SRSAddress::from_string("SRS1=GGG=orig.hostname==HHH=TT=orig-domain-part=orig-local-part@domain-part");

        assert!(r.is_ok());
        let a = r.unwrap();
        println!("{:?}", a);
        assert!(a.is_1());

        let a = a.SRS1();
        assert!(a.hash == "GGG");
        assert!(a.hostname == "orig.hostname");

    }

    #[test]
    fn it_reports_missing_trailing_separators_as_error() {
        let r = SRSAddress::from_string("SRS1=HHH=somehost=opaque");
        assert!(r.is_err());
        let r = SRSAddress::from_string("SRS0=HHH=TT=somehostlocal@domain");
        assert!(r.is_err());
    }

}

