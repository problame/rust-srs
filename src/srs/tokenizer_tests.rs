#[cfg(test)]
mod test {

    use srs::tokenizer::{Tokenizer,Token};
    use srs::tokenizer::Token::*;

    fn assert_tokenize(input: &str, expected: Vec<Token> ) {
        let t = Tokenizer::tokenize(input);
        let result: Vec<Token> = t.collect();

        if result != expected {
            println!{"Not equal:\n\tE: {:?}\n\tR: {:?}", expected, result};
        }
        assert!(result == expected);
    }

    #[test]
    fn it_tokenizes_complex_examples() {
        assert_tokenize("SOME=foo==lala@user@example.com",
                        vec![
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
                        ]);
    }

    #[test]
    fn it_tokenizes_empty_string() {
        assert_tokenize("", vec![]);
    }

    #[test]
    fn it_tokenizes_without_local_domain_separator() {
        assert_tokenize("user==foo", vec![
            Text("user"),SRSSeparator,SRSSeparator,Text("foo"),
        ]);
    }
}
