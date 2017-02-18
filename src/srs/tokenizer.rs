pub struct Tokenizer<'a> {
    input: &'a str,
    idx: usize,
    srs_separator: String,
    local_domain_separator: String,
}

impl<'a> Tokenizer<'a> {
    pub fn tokenize(input: &'a str, srs_sep: &str, ld_sep: &str) -> Tokenizer<'a> {
        let t = Tokenizer{
            input: input,
            idx: 0,
            srs_separator: srs_sep.to_string(),
            local_domain_separator: ld_sep.to_string(),
        };
        return t;
    }

    pub fn text_of_token(&self, token: &Token) -> String {
        use srs::tokenizer::Token::*;
        match token {
            &SRSSeparator => self.srs_separator.clone(),
            &LocalDomainSeparator => self.local_domain_separator.clone(),
            &SRS(x) => x.to_string(),
            &Text(t) => t.to_string(),
        }
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
        let S = &self.srs_separator;
        let L = &self.local_domain_separator;
        let next_char  = &match_text[0..1];
        let (token, move_chars) = {
            if next_char == self.srs_separator  {
                (Token::SRSSeparator, 1)
            } else if next_char == self.local_domain_separator {
                (Token::LocalDomainSeparator, 1)
            } else {
                // Move forward until one of the above is found
                let l = match_text.len();
                let next_srs_sep =
                    match_text
                    .find(&self.srs_separator).unwrap_or(l);
                let next_local_domain_sep =
                    match_text
                    .find(&self.local_domain_separator).unwrap_or(l);

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
