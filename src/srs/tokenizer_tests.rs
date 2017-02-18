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

    #[test]
    fn it_parses_srs_tokens() {
        assert_tokenize("SRS1=something", vec![SRS(1),SRSSeparator,Text("something")]);
        assert_tokenize("SRS0=something", vec![SRS(0),SRSSeparator,Text("something")]);
        assert_tokenize("something=SRS0", vec![Text("something"),SRSSeparator,SRS(0)]);
        assert_tokenize("something=SRS1", vec![Text("something"),SRSSeparator,SRS(1)]);
    }

    #[test]
    fn it_doesnt_parse_srs_substring() {
        assert_tokenize("SRS1substring=foo", vec![
            Text("SRS1substring"),SRSSeparator,Text("foo")
        ]);
    }
}
