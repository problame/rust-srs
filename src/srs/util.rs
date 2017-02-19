#[derive(Debug)]
pub enum Base64Err {
    PaddingErr(usize), // Pad to multiple of n bytes
    DecodingErr,
}

pub fn base64_email_safe_encode(b: &[u8]) -> Result<String, Base64Err> {

    let base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".as_bytes();

    let blen = b.len();

    if blen == 0 {
        return Ok("".to_string());
    } else if blen % 3 != 0 {
        return Err(Base64Err::PaddingErr(3));
    }


    let mut s = String::with_capacity((blen / 3) * 4);

    // 3 octets = 24 bits = 4 sixtets = 4 base64 chars
    let mut idx = 0;
    let mut c = vec![0,0,0,0];
    while idx != blen {
        c[0] = base64[(b[idx]>>2) as usize];
        c[1] = base64[((b[idx] & 0x3) << 4 | (b[idx+1]>>4)) as usize];
        c[2] = base64[(((b[idx+1] & 0x0f) << 2) | (b[idx+2] >> 6)) as usize];
        c[3] = base64[(b[idx+2] & 0x3f) as usize];
        let quad = &String::from_utf8_lossy(&c);
        s.push_str(quad);
        idx += 3;
    }

    return Ok(s);
}

pub fn base64_email_safe_decode(s: &str) -> Result<Vec<u8>, Base64Err> {

    let c = s.as_bytes();
    let clen = c.len();

    match clen {
        0 => return Ok(Vec::new()),
        x if x % 4 != 0 => return Err(Base64Err::PaddingErr(4)),
        _ => (),
    }

    let mut b = Vec::with_capacity((c.len() / 4) * 3);

    let mut idx = 0;
    while idx < c.len() {

        fn map_ascii_to_6_bit(a: u8) -> Result<u8, Base64Err> {
            if a >= 65 && a <= 90{ // A-Z
                Ok(a-65)
            } else if a >= 97 && a <= 122 { // a-z
                Ok(26 + a - 97)
            } else if a >= 48 && a <= 57 { // 0-9
                Ok(26 + 26 + a - 48)
            } else if a == 45 { // -
                Ok(26 + 26 + 10)
            } else if a == 95 { // _
                Ok(26 + 26 + 10 + 1)
            } else {
                Err(Base64Err::DecodingErr)
            }
        }

        let b0 = try!(map_ascii_to_6_bit(c[idx+0]));
        let b1 = try!(map_ascii_to_6_bit(c[idx+1]));
        let b2 = try!(map_ascii_to_6_bit(c[idx+2]));
        let b3 = try!(map_ascii_to_6_bit(c[idx+3]));

        b.push(b0 << 2 | b1 >> 4);
        b.push(b1 << 4 | b2 >> 2);
        b.push(b2 << 6 | b3);

        idx += 4;
    }

    return Ok(b);
}


#[cfg(test)]
mod test {

    use super::{base64_email_safe_encode,base64_email_safe_decode};

    #[test]
    fn test_base64() {

        fn e(x: &str) -> String {
            base64_email_safe_encode(x.as_bytes())
                .expect("encoding should work in this test")
        }

        assert!(e("Man") == "TWFu");
        assert!(e("") == "");
    }

    #[test]
    fn it_base64_encodes_only_supports_lengths_multiples_of_3() {
        let r = base64_email_safe_encode("four".as_bytes());
        assert!(r.is_err());
    }

    #[test]
    fn it_base64_decodes() {
        fn d(x: &str) -> String {
            let d = base64_email_safe_decode(x)
                .expect("should decode in this test");
            String::from_utf8(d).expect("decoding should produce ASCII")
        }
        assert!(d("TWFu") == "Man");
        assert!(d("") == "");
    }

    #[test]
    fn it_can_decode_its_encoding() {
        let enc = base64_email_safe_encode("Man".as_bytes()).expect("should encode");
        let dec = base64_email_safe_decode(&enc).expect("should decode");
        let dec_str = &String::from_utf8(dec).expect("decoding should produce ASCII");
        assert!(dec_str == "Man");
    }

}


