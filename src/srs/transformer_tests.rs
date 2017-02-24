#[cfg(test)]
mod transformer_tests {

    extern crate openssl;

    use srs::transformers::{Receiver,ReceiverError,Forwarder,ForwarderError};
    use srs::parser::SRSAddress;
    use openssl::hash::MessageDigest;

    fn make_receiver(key: &str, hostname: &str) -> Receiver {
        return Receiver::new(
            key.to_owned().into_bytes(),
            hostname.to_owned().into_bytes(),
            MessageDigest::sha512()
            ).expect("test should assert receiver params are ok");
    }

    fn expect_receive(receiver: &Receiver, input: &str, expect: &str) {
        let input_srs = SRSAddress::from_string(input)
            .expect("test should supply valid srs addresss");
        println!("{:?}", input_srs);
        let receive = receiver.receive(&input_srs).expect("test should supply valid receive");
        println!("receive = {:?}", receive);
        assert!(receive == expect);
    }

    fn expect_receive_err<F>(receiver: &Receiver, input: &str, match_err: F)
        where F: FnOnce(ReceiverError) -> bool {
        let input_srs = SRSAddress::from_string(input)
            .expect("test should supply valid srs addresss");
        let receive = receiver.receive(&input_srs);
        assert!(receive.is_err());
        let receive = receive.unwrap_err();
        assert!(match_err(receive) == true);
    }

    #[test]
    fn it_rewrites_srs1_to_srs0_to_plain() {
        let b = make_receiver("bsecret", "b");
        let c = make_receiver("csecret", "c");
        // IRL, these would occurr in reverse order
        expect_receive(&b, "SRS0=M59m=TT=a=user@b", "user@a");
        expect_receive(&c, "SRS1=nAM6=b==M59m=TT=a=user@c",  "SRS0=M59m=TT=a=user@b");
    }

    #[test]
    fn it_validates_srs0_hmac_and_reports_expected_hmac_on_failure() {
        let b = make_receiver("asecret", "b");
        let check_error = |r| match r {
            ReceiverError::HashVerificationFailed(correct) => {
                println!("received hash verification error: should have been: {:?}", correct);
                correct == "uNjN".to_string()
            },
            _ => false,
        };
        expect_receive_err(&b, "SRS0=HHHH=TT=a=user@b", check_error);
    }

    #[test]
    fn it_validates_srs1_hmac_and_reports_expected_hmac_on_failure() {
        let c = make_receiver("csecret", "c");
        let check_error = |r| match r {
            ReceiverError::HashVerificationFailed(correct) => {
                println!("received hash verification error: should have been: {:?}", correct);
                correct == "nAM6".to_string()
            },
            _ => false,
        };
        expect_receive_err(&c, "SRS1=HHHH=b==M59m=TT=a=user@c", check_error);
    }

    fn make_forwarder(key: &str, hostname: &str) -> Forwarder {
        return Forwarder::new(
            key.to_owned().into_bytes(),
            hostname.to_owned().into_bytes(),
            MessageDigest::sha512()
            ).expect("test should assert receiver params are ok");
    }

    #[test]
    fn it_adds_srs0_prefix() {

        let f = make_forwarder("asecret", "a");

        use srs::transformers::{ForwardableAddress,Forwarder};

        let plain = ForwardableAddress::Plain{
            local: "user".to_string(),
            domain: "origin".to_string(),
        };

        let res = f.forward(plain);

        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(res.is_0());
        let mut res = res.srs0();
        assert!(res.hostname == "origin");
        assert!(res.local == "user");
        assert!(res.domain == "a");

        // Verify hash is correct
        let r = make_receiver("asecret", "a");
        let back = r.receive(&SRSAddress::SRS0(res));
        assert!(back.is_ok());

    }

    #[test]
    fn it_adds_srs1_prefix_to_srs0() {
        let f = make_forwarder("bsecret", "b");

        use srs::transformers::{ForwardableAddress,Forwarder};
        use srs::parser::SRSAddress::{SRS0,SRS1};
        use srs::parser::SRS0Address;

        let srs0 = ForwardableAddress::SRS(SRS0(SRS0Address{
            hash: "HHHH".to_string(),
            tt: "TT".to_string(),
            hostname: "origin".to_string(),
            local: "user".to_string(),
            domain: "a".to_string(),
        }));

        let res = f.forward(srs0);

        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(res.is_1());
        let mut res = res.srs1();

        assert!(res.hostname == "a");
        assert!(res.domain == "b");
        // assert!(res.opaque_local ==  yeah what, we don't know the separator -> TODO

        let r = make_receiver("bsecret", "b");
        let back = r.receive(&SRSAddress::SRS1(res));
        assert!(back.is_ok());

    }

    #[test]
    fn it_updates_domain_on_srs1_address() {
        let f = make_forwarder("csecret", "c");

        use srs::transformers::{ForwardableAddress,Forwarder};
        use srs::parser::SRSAddress::{SRS0,SRS1};
        use srs::parser::SRS1Address;

        let srs1 = ForwardableAddress::SRS(SRS1(SRS1Address{
            hash: "HBHB".to_string(),
            hostname: "a".to_string(),
            opaque_local: "+HHHH+TT+origin+user".to_string(),
            domain: "b".to_string(),
        }));

        let res = f.forward(srs1);

        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(res.is_1());
        let res = res.srs1();
        println!("{:?}", res);
        assert!(res.domain == "c");
        assert!(res.hash == "HBHB");
        assert!(res.hostname == "a");
        // assert!(res.opaque_local == "HBHB yeah we don't know the separator -> TODO

    }

    #[test]
    fn it_handles_full_chain_simulation() {

        use srs::transformers::{ForwardableAddress,Forwarder};
        use srs::transformers::ForwardableAddress::{Plain,SRS};
        use srs::parser::SRSAddress;

        let plain = Plain{
            local: "user".to_string(),
            domain: "origin".to_string(),
        };
        println!("{:?}", plain);

        let f_a = make_forwarder("asecret", "a");
        let f_b = make_forwarder("bsecret", "b");
        let f_c = make_forwarder("csecret", "c");
        let r_a = make_receiver("asecret", "a");
        let r_b = make_receiver("bsecret", "b");
        let r_c = make_receiver("csecret", "c");

        let res = f_a.forward(plain)
            .and_then(|x| f_b.forward(SRS(x)))
            .and_then(|x| f_c.forward(SRS(x)));

        println!("{:?}", res);
        assert!(res.is_ok());
        let res = res.unwrap();

        let res = r_c.receive(&res);
        println!("{:?}", res);

        assert!(res.is_ok());
        let res = res.unwrap();
        let res = SRSAddress::from_string(res.as_str());
        assert!(res.is_ok());
        let res = r_a.receive(&res.unwrap());
        println!("{:?}", res);

        assert!(res.is_ok());
        let res= res.unwrap();

        println!("{:?}", res);

    }


}
