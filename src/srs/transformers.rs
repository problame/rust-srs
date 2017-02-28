extern crate openssl;

use self::openssl::hash::MessageDigest;
use self::openssl::pkey::PKey;
use self::openssl::sign::Signer;
use self::openssl::error::ErrorStack;

use std::ascii::AsciiExt;

use srs::parser::{SRSAddress,SRS1Address,SRS0Address};
use srs::parser::SRSAddress::{SRS0,SRS1};
use srs::util::{base64_email_safe_encode,base64_email_safe_decode};

use std::time;
use std::i32;

/* A SHORT EXAMPLE:
 *
 * A to B: MAIL FROM user@a
 * B to C: MAIL FROM SRS0=HHH1=TT=a=user@b
 * C to D: MAIL FROM SRS1=HHH2=b=HHH1=TT=a=user@c
 * D to E: MAIL FROM SRS1=HHH2=b=HHH1=TT=a=user@d
 *
 * E bounces => route to SRS1=HHH2=b=HHH1=TT=a=user@d is rewritten to SRS0=HHH1=TT=a=user@b
 * E TO B: MAIL FROM SRS0=HHH1=TT=a=user@b
 * B rewrites SRS0=HHH1=TT=a=user@b to user@a
 * B TO A: MAIL FROM user@a
 *
 * => the return path is exactly 3 hops long, shortcircuits all the intermediate hosts
 *
 */

pub trait Timestamper {
    fn verify_timestamp(&self, ts: &str) -> Result<(), i32>;
    fn now_as_timestamp(&self) -> String;
}

pub struct SRSTimestamper {
    pub max_valid_delta: u16,
}

impl SRSTimestamper {
   pub fn now_in_days_10bit() -> u16 {
        let secs_since_epoch = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .expect("UNIX_EPOCH is always earlier than current time")
            .as_secs();
        // Break this down to days that fit into 10 bit
        // => wraparound after > 3 years is fine
        let days = (secs_since_epoch / (60 * 60 * 24)) % 1024;
        assert!(days < 1024);
        return days as u16;
    }

   pub fn base32_email_safe_decode_10bit(s: &str) -> Result<u16,()> {
        let lowercase = s.to_ascii_lowercase();
        let bytes = lowercase.as_bytes();
        assert!(bytes.len() >= 2);
        let mut res: u16 = 0;

        fn lowercase_ascii_to_value(a: u8) -> Result<u8, ()> {
            if a >= 97 && a <= 122 { // a to z
                return Ok(a - 97);
            }
            if a >= 50 && a <= 55 { // 2 to 5
                return Ok(26 + a - 50);
            }
            return Err(());
        }

        let val_low = try!(lowercase_ascii_to_value(bytes[0]));
        let val_high = try!(lowercase_ascii_to_value(bytes[1]));
        assert!(val_low < 32);
        assert!(val_high < 32);
        res = val_high as u16;
        res = res << 5;
        res |= val_low as u16;
        return Ok(res);
    }

    pub fn base32_email_safe_encode_10bit(b: u16) -> String {

        let mut bytes = Vec::with_capacity(2);
        bytes.push((b & 0x1f) as u8);
        bytes.push(((b >> 5) & 0x1f) as u8);

        for b in &mut bytes {
            if *b <= 25 { // map to a to z
                *b = *b + 97;
            } else if *b <= 31 { // map to 2 to 5
                *b = *b - 26 + 50;
            } else {
                panic!("base32 only maps values [0,32) to ASCII bytes");
            }
        }

        return String::from_utf8(bytes).expect("routine should only produce ASCII bytes");
    }

}

impl Timestamper for SRSTimestamper  {

      fn verify_timestamp(&self, ts: &str) -> Result<(), i32> {
        let now = Self::now_in_days_10bit();
        let days_ts = match Self::base32_email_safe_decode_10bit(ts) {
            Ok(d)  => d,
            Err(_) => {
                return Err(i32::MAX); // TODO hardcoded magic number
            },
        };
        let abs_delta = match now > days_ts {
            true => (now as i32) - (days_ts as i32),
            false => (days_ts as i32) - (now as i32),
        };

        if abs_delta > self.max_valid_delta as i32  {
            return Err(abs_delta);
        }
        return Ok(());
    }

    fn now_as_timestamp(&self) -> String {
        let now = Self::now_in_days_10bit();
        return Self::base32_email_safe_encode_10bit(now);
    }

}

pub struct Receiver<T> where T: Timestamper {
    secret_pkey: PKey,
    pub hostname: Vec<u8>,
    pub md: MessageDigest,
    pub timestamper: T,
}

#[derive(Debug)]
pub enum ReceiverError {
    HashVerificationFailed(String),
    HashingError(ErrorStack),
    TimestampError(i32),
}

#[derive(Debug)]
pub enum ReceiverInitializationError {
    HostnameInvalidChars,
}

fn is_email_compatible_ascii(substr: &[u8]) -> bool {
    // TODO
    // https://tools.ietf.org/html/rfc5321
    // https://tools.ietf.org/html/rfc822
    // https://en.wikipedia.org/wiki/Email_address
    return true;
}

fn is_valid_srs_separator(separator: &str) -> bool {
    match separator {
        "=" | "+" | "-" => true,
        _               => false,
    }
}

fn compute_addr_hash(key: &PKey, md: &MessageDigest, address: &SRSAddress) -> Result<String,ErrorStack> {

    let mut signer = try!(Signer::new(md.clone(), key));

    match *address {
        SRSAddress::SRS0(ref a) => {
            try!(signer.update(a.tt.as_bytes()));
            try!(signer.update(a.hostname.as_bytes()));
            try!(signer.update(a.local.as_bytes()));
        },
        SRSAddress::SRS1(ref a) => {
            try!(signer.update(a.hostname.as_bytes()));
            try!(signer.update(a.opaque_local.as_bytes()));
        },
    }

    let hmac = try!(signer.finish());

    let hmac_base64_prefix = base64_email_safe_encode(&hmac[0..3])
        .expect("caller asserts length multiple of 3");

    return Ok(hmac_base64_prefix);

}

impl<T> Receiver<T> where T: Timestamper {

    pub fn new(secret: Vec<u8>, hostname: Vec<u8>, md: MessageDigest, timestamper: T) -> Result<Receiver<T>, ReceiverInitializationError> {

        if !is_email_compatible_ascii(&hostname) {
            return Err(ReceiverInitializationError::HostnameInvalidChars);
        }
        // TODO if contains srs separator discard

        // TODO key derivation?
        // Create a PKey
        let secret_pkey = PKey::hmac(secret.as_ref()).unwrap();

        return Ok(Receiver{
            secret_pkey: secret_pkey,
            hostname: hostname,
            md: md,
            timestamper: timestamper,
        });
    }

    pub fn receive(&self, address: &SRSAddress) -> Result<String, ReceiverError> {

        let expected_hash = match compute_addr_hash(&self.secret_pkey, &self.md, &address) {
            Err(es) => return Err(ReceiverError::HashingError(es)),
            Ok(x) => x,
        };

        let hash = match address {
            &SRSAddress::SRS0(ref a) => a.hash.as_str(),
            &SRSAddress::SRS1(ref a) => a.hash.as_str(),
        };
        if !expected_hash.eq_ignore_ascii_case(hash) {
            return Err(ReceiverError::HashVerificationFailed(expected_hash));
        }

        if let SRS0(ref a) = *address {
            match self.timestamper.verify_timestamp(a.tt.as_str()) {
                Ok(())      => {},
                Err(delta)  => {
                    return Err(ReceiverError::TimestampError(delta));
                }
            }
        }

        return match *address {
            SRSAddress::SRS0(ref a) => {
                let mut rewritten = String::with_capacity(a.local.len() + a.hostname.len() + 1);
                rewritten.push_str(&a.local);
                rewritten.push_str("@");
                rewritten.push_str(&a.hostname);
                Ok(rewritten)
            },
            SRSAddress::SRS1(ref a) => {
                let mut rewritten = String::with_capacity(4 + a.opaque_local.len() + 1 + a.hostname.len());
                rewritten.push_str("SRS0");
                rewritten.push_str(&a.opaque_local); // contains a.hostname's separator
                rewritten.push_str("@");
                rewritten.push_str(&a.hostname);
                Ok(rewritten)
            }
        };
    }
}



pub struct Forwarder<T> where T: Timestamper {
    secret_pkey: PKey,
    pub hostname: Vec<u8>,
    pub md: MessageDigest,
    pub separator: String,
    pub timestamper: T,
}

#[derive(Debug)]
pub enum ForwarderInitializationError {
    HostnameInvalidChars,
    InvalidSRSSeparator,
}

#[derive(Debug)]
pub enum ForwarderError {
    HashingError(ErrorStack),
}

#[derive(Debug)]
pub enum ForwardableAddress {
    SRS(SRSAddress),
    Plain{
        local: String,
        domain: String
    },
}

impl<T> Forwarder<T> where T: Timestamper {

    pub fn new(secret: Vec<u8>, hostname: Vec<u8>, md: MessageDigest, separator: &str, timestamper: T) -> Result<Forwarder<T>,ForwarderInitializationError> {

        if !is_email_compatible_ascii(&hostname) {
            return Err(ForwarderInitializationError::HostnameInvalidChars);
        }

        if !is_valid_srs_separator(separator) {
            return Err(ForwarderInitializationError::InvalidSRSSeparator);
        }

        let secret_key = PKey::hmac(secret.as_ref()).unwrap();

        return Ok(Forwarder{
            separator: separator.to_string(),
            secret_pkey: secret_key,
            hostname: hostname,
            md: md,
            timestamper: timestamper,
        });
    }

    fn update_hash(&self, address: &mut SRSAddress) -> Result<(), ForwarderError> {
        let hash = match compute_addr_hash(&self.secret_pkey, &self.md, &address) {
            Err(es) => return Err(ForwarderError::HashingError(es)),
            Ok(x) => x,
        };
        match *address {
            SRS0(ref mut a) => a.hash = hash,
            SRS1(ref mut a) => a.hash = hash,
        }
        return Ok(());
    }

    pub fn forward(&self, address: ForwardableAddress) -> Result<SRSAddress,ForwarderError> {

        let hostname = String::from_utf8(self.hostname.clone())
            .expect("should be valid utf8, be checked at compile time");

        use self::ForwardableAddress::{SRS,Plain};
        let rewritten: SRSAddress = match address {
            Plain{local, domain} => {
                let mut srs0 = SRS0(SRS0Address{
                    separator: self.separator.clone(),
                    hash: "".to_string(), // updated below
                    tt: self.timestamper.now_as_timestamp(),
                    hostname: domain,
                    local: local,
                    domain: hostname,
                });
                try!(self.update_hash(&mut srs0));
                srs0
            },
            SRS(SRS0(srs0)) => {
                let opaque_local = format!("{}{}{}{}{}{}{}{}",
                                           srs0.separator,
                                           srs0.hash, srs0.separator,
                                           srs0.tt, srs0.separator,
                                           srs0.hostname, srs0.separator,
                                           srs0.local);
                let mut srs1 = SRS1(SRS1Address{
                    separator: self.separator.clone(),
                    hash: "".to_string(), // updated below
                    hostname: srs0.domain,
                    opaque_local: opaque_local,
                    domain: hostname,
                });
                try!(self.update_hash(&mut srs1));
                srs1
            },
            SRS(SRS1(srs1)) => {
                let mut srs1 = srs1.clone();
                srs1.domain = hostname;
                SRS1(srs1)
            },
        };

        return Ok(rewritten);
    }

}

