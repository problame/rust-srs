#[cfg(test)]
mod test {

    use srs::{SRSAddress,SRSParser,SRSParserResult};

    //fn new_parser_result(s: &str) -> SRSParserResult {
    //}

    #[test]
    fn it_parses_srs0() {
        let r = SRSAddress::from_string("SRS0=HHH=TT=source.com=user@forwarder=theoreticallylegit");

        println!("{:?}", r);
        assert!(r.is_ok());
        let a = r.unwrap();
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

        println!("{:?}", r);
        assert!(r.is_ok());
        let a = r.unwrap();
        println!("{:?}", a);
        assert!(a.is_1());

        let a = a.SRS1();
        assert!(a.hash == "GGG");
        assert!(a.hostname == "orig.hostname");
        assert!(a.opaque_local == "=HHH=TT=orig-domain-part=orig-local-part");
        assert!(a.domain == "domain-part");
    }

    #[test]
    fn it_does_not_accept_empty_locals_for_srs1() {
        let r = SRSAddress::from_string("SRS1=HHH=somehost=");
        assert!(r.is_err());
    }
   
    #[test]
    fn it_does_not_accept_empty_locals_for_srs0() {
        let r = SRSAddress::from_string("SRS0=HHH=TT=somehostlocal@domain");
        assert!(r.is_err());
    }

}

