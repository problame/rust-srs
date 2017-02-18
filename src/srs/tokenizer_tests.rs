#[cfg(test)]
mod test {

    use srs::tokenizer::{Tokenizer,Token};

    #[test]
    fn it_disassembles_a_string() {
        let t = Tokenizer::tokenize("SOME=foo==lala@user@example.com");

        use srs::tokenizer::Token::*;

        let expected = vec![
            Text("SOME"),
            SRSSeparator,
            Text("foo"),
            SRSSeparator,
            SRSSeparator,
            Text("lala"),
            LocalDomainSeparator,
            Text("user"),
            LocalDomainSeparator,
            Text("example.com")
        ];
        let c: Vec<Token> = t.collect();
        println!("");
        println!("{:?}", expected);
        println!("{:?}", c);
        assert!(c == expected);

    }
}
