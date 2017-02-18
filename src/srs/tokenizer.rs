pub struct Tokenizer<'a> {
    input: &'a str,
    idx: usize,
}

impl<'a> Tokenizer<'a> {
    pub fn tokenize(input: &'a str) -> Tokenizer<'a> {
        let t = Tokenizer{
            input: input,
            idx: 0
        };
        return t;
    }
}

#[derive(Debug,PartialEq)]
pub enum Token<'a> {
    SRSSeparator,
    LocalDomainSeparator,
    SRS(usize),
    Text(&'a str),
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Token<'a>> {

        if self.idx == self.input.len() {
            return None;
        }

        let match_text = &self.input[self.idx..];
        let (token, move_chars) = match &match_text[0..1] {
            "=" => (Token::SRSSeparator, 1),
            "@" => (Token::LocalDomainSeparator, 1),
            _   => {
                // Move forward until one of the above is found
                let l = match_text.len();
                let next_srs_sep = match_text.find("@").unwrap_or(l);
                let next_local_domain_sep = match_text.find("=").unwrap_or(l);

                use std::cmp::min;
                let mut move_chars = min(next_srs_sep, next_local_domain_sep);

                let token_text = &match_text[..move_chars];
                let token = match token_text {
                    "SRS0" => Token::SRS(0),
                    "SRS1" => Token::SRS(1),
                    _      => Token::Text(token_text),
                };
                (token, move_chars)
            }
        };

        self.idx += move_chars;

        return Some(token);
    }
}
