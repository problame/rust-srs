#[cfg(test)]
mod parser_tests {

    use srs::parser::SRSAddress;

    //fn new_parser_result(s: &str) -> SRSParserResult {
    //}

    #[test]
    fn it_parses_basic_srs0() {
        let r = SRSAddress::from_string("SRS0=HHH=TT=source.com=user@forwarder=theoreticallylegit");

        println!("{:?}", r);
        assert!(r.is_ok());
        let a = r.unwrap();
        assert!(a.is_0());
        let a = a.srs0();
        assert!(a.separator == "=");
        assert!(a.hash == "HHH");
        assert!(a.tt == "TT");
        assert!(a.hostname == "source.com");
        assert!(a.local == "user");
        assert!(a.domain == "forwarder=theoreticallylegit");
    }

    #[test]
    fn it_handles_mixed_separators_srs0() {

        let seps = vec!["=", "-", "+"];
        for sep in seps {
            let a = format!("SRS0{}HHH{}TT{}source.com{}user{}prevcharnotspf@forwarder{}prevcharnotspf",
                            sep, sep, sep, sep, sep, sep);
            println!("{:?}", a);
            let r = SRSAddress::from_string(&a);
            println!("{:?}", r);
            assert!(r.is_ok());
            let r = r.unwrap();
            assert!(r.is_0());
            let r = r.srs0();
            assert!(r.hash == "HHH");
            assert!(r.tt == "TT");
            assert!(r.hostname == "source.com");
            assert!(r.local == format!("user{}prevcharnotspf", sep));
            assert!(r.domain == format!("forwarder{}prevcharnotspf", sep));
            assert!(r.separator == sep);
        }
    }

    #[test]
    fn it_parses_basic_srs1() {
        let r = SRSAddress::from_string("SRS1=GGG=orig.hostname==HHH=TT=orig-domain-part=orig-local-part@domain-part");

        println!("{:?}", r);
        assert!(r.is_ok());
        let a = r.unwrap();
        println!("{:?}", a);
        assert!(a.is_1());

        let a = a.srs1();
        assert!(a.hash == "GGG");
        assert!(a.hostname == "orig.hostname");
        assert!(a.opaque_local == "=HHH=TT=orig-domain-part=orig-local-part");
        assert!(a.domain == "domain-part");
    }

    #[test]
    fn it_handles_mixed_separators_srs1_srs0() {

        let seps = vec!["=", "-", "+"];
        for sep1 in &seps {
            for sep0 in &seps {
                println!("Separators: SRS1=sep1: {:?} SRS0=sep0: {:?}", sep1, sep0);
                let a = format!("SRS1{}GGG{}orig.hostname{}{}HHH{}TT{}orig-domain-part{}origlocalpart{}prevcharnotspf@domain{}prevcharnotspf",
                                sep1, sep1, sep1, sep0, sep0, sep0, sep0, sep1, sep1); // permuting last two seps would be even better...
                println!("{:?}", a);
                let r = SRSAddress::from_string(&a);
                println!("{:?}", r);
                assert!(r.is_ok());
                let r = r.unwrap();
                assert!(r.is_1());
                let r = r.srs1();
                assert!(r.separator == *sep1);
                assert!(r.hash == "GGG");
                assert!(r.hostname == "orig.hostname");
                assert!(r.opaque_local == format!("{}HHH{}TT{}orig-domain-part{}origlocalpart{}prevcharnotspf", sep0, sep0, sep0, sep0, sep1));
                assert!(r.domain == format!("domain{}prevcharnotspf", sep1));
                println!("");
            }
        }
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

