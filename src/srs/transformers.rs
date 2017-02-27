extern crate openssl;

use self::openssl::hash::MessageDigest;
use self::openssl::memcmp;
use self::openssl::pkey::PKey;
use self::openssl::sign::Signer;
use self::openssl::error::ErrorStack;

use std::ascii::AsciiExt;

use srs::parser::{SRSAddress,SRS1Address,SRS0Address};
use srs::parser::SRSAddress::{SRS0,SRS1};
use srs::util::{base64_email_safe_encode,base64_email_safe_decode};

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

pub struct Receiver {
    secret_pkey: PKey,
    pub hostname: Vec<u8>,
    pub md: MessageDigest,
}

#[derive(Debug)]
pub enum ReceiverError {
    HashVerificationFailed(String),
    HashingError(ErrorStack),
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

fn compute_addr_hash(key: &PKey, md: &MessageDigest, address: &SRSAddress) -> Result<String,ErrorStack> {

    let mut signer = try!(Signer::new(md.clone(), key));

    match *address {
        SRSAddress::SRS0(ref a) => {
            signer.update(a.tt.as_bytes());
            signer.update(a.hostname.as_bytes());
            signer.update(a.local.as_bytes());
        },
        SRSAddress::SRS1(ref a) => {
            signer.update(a.hostname.as_bytes());
            signer.update(a.opaque_local.as_bytes());
        },
    }

    let hmac = try!(signer.finish());

    let hmac_base64_prefix = base64_email_safe_encode(&hmac[0..3])
        .expect("caller asserts length multiple of 3");

    return Ok(hmac_base64_prefix);

}

impl Receiver {

    pub fn new(secret: Vec<u8>, hostname: Vec<u8>, md: MessageDigest) -> Result<Receiver, ReceiverInitializationError> {

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
        });
    }

    pub fn receive(&self, address: &SRSAddress) -> Result<String, ReceiverError> {

        let expected_hash = match compute_addr_hash(&self.secret_pkey, &self.md, &address) {
            Err(es) => return Err(ReceiverError::HashingError(es)),
            Ok(x) => x,
        };

        // Verify Hash
        let hash = match address {
            &SRSAddress::SRS0(ref a) => a.hash.as_str(),
            &SRSAddress::SRS1(ref a) => a.hash.as_str(),
        };

        if expected_hash != hash {
            return Err(ReceiverError::HashVerificationFailed(expected_hash));
        }

        return match *address {
            SRSAddress::SRS0(ref a) => {
                let mut rewritten = String::with_capacity(a.local.len() + a.hostname.len() + 1);
                rewritten.push_str(&a.local);
                rewritten.push_str("@"); // TODO fix hardcoding
                rewritten.push_str(&a.hostname);
                Ok(rewritten)
            },
            SRSAddress::SRS1(ref a) => {
                let mut rewritten = String::with_capacity(4 + a.opaque_local.len() + 1 + a.hostname.len());
                rewritten.push_str("SRS0");
                rewritten.push_str(&a.opaque_local); // contains a.hostname's separator
                rewritten.push_str("@"); // TODO fix hardcoding
                rewritten.push_str(&a.hostname);
                Ok(rewritten)
            }
        };
    }
}



pub struct Forwarder {
    secret_pkey: PKey,
    pub hostname: Vec<u8>,
    pub md: MessageDigest,
}

#[derive(Debug)]
pub enum ForwarderInitializationError {
    HostnameInvalidChars,
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

impl Forwarder {

    pub fn new(secret: Vec<u8>, hostname: Vec<u8>, md: MessageDigest) -> Result<Forwarder,ForwarderInitializationError> {

        if !is_email_compatible_ascii(&hostname) {
            return Err(ForwarderInitializationError::HostnameInvalidChars);
        }

        let secret_key = PKey::hmac(secret.as_ref()).unwrap();

        return Ok(Forwarder{
            secret_pkey: secret_key,
            hostname: hostname,
            md: md
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
        let mut rewritten: SRSAddress = match address {
            Plain{local, domain} => {
                let mut srs0 = SRS0(SRS0Address{
                    separator: "=".to_string(), // TODO fix hardcoded
                    hash: "".to_string(), // updated below
                    tt: "TODO".to_string(),
                    hostname: domain,
                    local: local,
                    domain: hostname,
                });
                self.update_hash(&mut srs0);
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
                    separator: srs0.separator,
                    hash: "".to_string(), // updated below
                    hostname: srs0.domain,
                    opaque_local: opaque_local,
                    domain: hostname,
                });
                self.update_hash(&mut srs1);
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

