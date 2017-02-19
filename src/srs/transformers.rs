extern crate openssl;

use self::openssl::hash::MessageDigest;
use self::openssl::memcmp;
use self::openssl::pkey::PKey;
use self::openssl::sign::Signer;
use self::openssl::error::ErrorStack;

use std::ascii::AsciiExt;

use srs::parser::SRSAddress;
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
    CreateSigner(ErrorStack),
}

#[derive(Debug)]
pub enum ReceiverInitializationError {
    HostnameInvalidChars,
}

impl Receiver {

    fn is_email_compatible_ascii(substr: &[u8]) -> bool {
        // TODO
        // https://tools.ietf.org/html/rfc5321
        // https://tools.ietf.org/html/rfc822
        // https://en.wikipedia.org/wiki/Email_address
        return true;
    }

    pub fn new(secret: Vec<u8>, hostname: Vec<u8>, md: MessageDigest) -> Result<Receiver, ReceiverInitializationError> {

        if !Self::is_email_compatible_ascii(&hostname) {
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

        // Compute the HMAC
        let mut signer = try!(match Signer::new(self.md.clone(), &self.secret_pkey) {
            Ok(s) => Ok(s),
            Err(stack) => Err(ReceiverError::CreateSigner(stack)),
        });

        match address {
            &SRSAddress::SRS0(ref a) => {
                signer.update(a.tt.as_bytes());
                signer.update(a.hostname.as_bytes());
                signer.update(a.local.as_bytes());
            },
            &SRSAddress::SRS1(ref a) => {
                signer.update(a.hostname.as_bytes());
                signer.update(a.opaque_local.as_bytes());
            },
        }

        let hmac = signer.finish().unwrap();
        let hmac = base64_email_safe_encode(&hmac[0..3])
            .expect("caller asserts length multiple of 3");

        // Verify Hash
        let hash = match address {
            &SRSAddress::SRS0(ref a) => a.hash.as_str(),
            &SRSAddress::SRS1(ref a) => a.hash.as_str(),
        };

        if hmac != hash {
            return Err(ReceiverError::HashVerificationFailed(hmac));
        }

        return match address {
            &SRSAddress::SRS0(ref a) => {
                let mut rewritten = String::with_capacity(a.local.len() + a.hostname.len() + 1);
                rewritten.push_str(&a.local);
                rewritten.push_str("@"); // TODO fix hardcoding
                rewritten.push_str(&a.hostname);
                Ok(rewritten)
            },
            &SRSAddress::SRS1(ref a) => {
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
