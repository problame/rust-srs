#[cfg(test)]
mod transformer_tests {

    extern crate openssl;

    use srs::transformers::{Receiver,ReceiverError};
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





}
