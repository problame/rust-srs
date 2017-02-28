#[cfg(test)]
mod transformer_tests {

    extern crate openssl;

    use srs::transformers::{Receiver,ReceiverError,Forwarder,ForwarderError,Timestamper,SRSTimestamper};
    use srs::parser::SRSAddress;
    use openssl::hash::MessageDigest;

    struct MockTimestamper {
        pub verify: Box<Fn(&str) -> Result<(), i32>>,
        pub now: Box<Fn() -> String>,
    }
    impl Timestamper for MockTimestamper {
        fn verify_timestamp(&self, ts: &str) -> Result<(), i32> { (self.verify)(ts) }
        fn now_as_timestamp(&self) -> String { (self.now)() }
    }

    fn make_receiver(key: &str, hostname: &str) -> Receiver<MockTimestamper> {
        return Receiver::new(
            key.to_owned().into_bytes(),
            hostname.to_owned().into_bytes(),
            MessageDigest::sha512(),
            MockTimestamper{
                verify: Box::new(|ts| Ok(())),
                now: Box::new(|| "AA".to_string()),
            },
            ).expect("test should assert receiver params are ok");
    }

    fn expect_receive<T>(receiver: &Receiver<T>, input: &str, expect: &str)
      where T: Timestamper {
        let input_srs = SRSAddress::from_string(input)
            .expect("test should supply valid srs addresss");
        println!("{:?}", input_srs);
        let receive = receiver.receive(&input_srs).expect("test should supply valid receive");
        println!("receive = {:?}", receive);
        assert!(receive == expect);
    }

    fn expect_receive_err<F,T>(receiver: &Receiver<T>, input: &str, match_err: F)
        where F: FnOnce(ReceiverError) -> bool,
              T: Timestamper {
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

    #[test]
    fn it_allows_changed_case_in_hmac() {
        // From shevek's paper:
        //  The cryptographic hashes are encoded in base 64, but are compared case insensitively.
        //  The implementation will issue a warning if it detects that a remote MTA has smashed case, but this will
        //  not affect the functionality of the code. Timestamps are encoded in base 32.
        let b = make_receiver("bsecret", "b");
        expect_receive(&b, "SRS0=m59m=TT=a=user@b", "user@a");
    }

    #[test]
    fn it_uses_the_timestamper_to_check_timestamp() {
        let mut b = make_receiver("bsecret", "b");
        b.timestamper = MockTimestamper{
            verify: Box::new(|ts| match ts == "ac" {
                true => Ok(()),
                false => Err(23),
            }),
            now: Box::new(|| panic!("shouldn't be called")),
        };
        expect_receive(&b, "SRS0=pt9d=ac=a=user@b", "user@a");
        expect_receive_err(&b, "SRS0=tH4m=ae=a=user@b", |e| match e {
            ReceiverError::TimestampError(23) => true,
            x => {
                println!("{:?}", x);
                false
            }
        });
    }

    fn make_forwarder(key: &str, hostname: &str) -> Forwarder<MockTimestamper>{
        return Forwarder::new(
            key.to_owned().into_bytes(),
            hostname.to_owned().into_bytes(),
            MessageDigest::sha512(),
            "=",
            MockTimestamper{
                verify: Box::new(|ts| Err(23)),
                now: Box::new(|| "aa".to_string()),
            },
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
            separator: "+".to_string(),
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
            separator: "=".to_string(),
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

        // Now two ways of bounce can happen
        //  1) Whoever C forwarded to rejects in SMTP conversation
        //     => the MTA at C must send abounce to B
        //  2) Whoever C forwarded to generates a bounce afterwards
        //     => their MTA will send a bounce to
        //        2.1  | understands SRS => B, which can verify the hash and pass the bounce to A
        //        2.2. | otherwise       => C, which cannot verify the hash and should notify the
        //                                  admin of C, but not notify B or A
        // 2.2 sounds messy, but it's orthogonal to SPF
        // -> for this test, only 2.1 is relevant
        let res = r_b.receive(&res);
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

    #[test]
    fn srstimestamper_respects_max_valid_delta() {
        let mut t = SRSTimestamper {
            max_valid_delta: 3
        };

        let now = SRSTimestamper::now_in_days_10bit();
        let good_date = (now + 3) % 1024;
        let bad_date  = (now + 6) % 1024;

        let good_ts = SRSTimestamper::base32_email_safe_encode_10bit(good_date);
        let bad_ts = SRSTimestamper::base32_email_safe_encode_10bit(bad_date);

        let r = t.verify_timestamp(&good_ts);
        println!("{:?}", r);
        assert!(r == Ok(()));

        let r = t.verify_timestamp(&bad_ts);
        println!("{:?}", r);
        assert!(r == Err(6));
    }

    #[test]
    fn srstimestamper_base32_works_for_example() {
        let t = SRSTimestamper {
            max_valid_delta: 0
        };

        let enc = SRSTimestamper::base32_email_safe_encode_10bit(23);
        println!("enc: {}", enc);
        assert!(enc == "xa");
        let dec = SRSTimestamper::base32_email_safe_decode_10bit(&enc);
        assert!(dec.is_ok());
        let dec = dec.unwrap();
        println!("dec: {:b}", dec);
        assert!(dec == 23);

    }

    #[test]
    fn srstimestamper_base32_works_for_all_10bit_numbers() {
        let t = SRSTimestamper {
            max_valid_delta: 0
        };

        for i in  0..1024 {
            let enc = SRSTimestamper::base32_email_safe_encode_10bit(i);
            let dec = SRSTimestamper::base32_email_safe_decode_10bit(&enc);
            assert!(dec.is_ok());
            let dec = dec.unwrap();
            if dec != i {
                println!("i = {}, enc = {}, dec = {}", i, enc, dec);
                println!("enc: {}", enc);
                println!("dec: {:b}", dec);
                assert!(false);
            }
        }

    }


}
