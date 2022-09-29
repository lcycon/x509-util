use color_eyre::Result;
use std::{fmt::Display, str::FromStr};
use x509_util::prelude::Context;

lalrpop_mod!(
    #[allow(clippy::all)]
    name_parser
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedName(pub Vec<(String, String)>);

impl OwnedName {
    pub fn to_x509_name<'a>(
        &self,
        context: &'a Context,
    ) -> Result<x509_util::x509_cert::name::Name<'a>> {
        Ok(x509_util::name::Name::from_pairs(context, &self.0)?)
    }
}

impl FromStr for OwnedName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = name_parser::NameParser::new()
            .parse(s)
            .map_err(|e| e.to_string())?;

        let cont = result
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        Ok(OwnedName(cont))
    }
}

impl Display for OwnedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.0.iter().peekable();
        while let Some((k, v)) = iter.next() {
            f.write_str(k)?;
            f.write_str(" = ")?;
            f.write_str(v)?;

            // If peek gives us a Some, there's more elements to process
            if iter.peek().is_some() {
                f.write_str(", ")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    fn test_okay(input: &str) {
        let result: Result<super::OwnedName, _> = input.parse();

        assert!(result.is_ok());

        println!("Result: {}", result.unwrap());
    }

    #[test]
    fn parses_right() {
        test_okay("C=US,ST = CA, L =SF");
        test_okay("C=US,ST = \"CA Minor\", L =SF");
    }
}
