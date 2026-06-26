//! Common URL utilities
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use std::borrow::Cow;

pub fn convert_idn_with_default_scheme<'a>(
    url: &'a str,
    default_scheme: &str,
) -> Result<Cow<'a, str>, idna::Errors> {
    let url = if url.contains("://") {
        Cow::Borrowed(url)
    } else {
        Cow::Owned(format!("{default_scheme}://{url}"))
    };
    if url.is_ascii() {
        Ok(url)
    } else {
        let mut elements: Vec<&str> = url.split('/').collect();
        // This indexing cannot fail because we added :// before
        assert!(elements.len() >= 3);
        let idn_host = idna::domain_to_ascii(elements[2])?;
        elements[2] = &idn_host;
        let idn_url = elements.join("/");
        Ok(Cow::Owned(idn_url))
    }
}

#[cfg(test)]
mod tests {
    use super::convert_idn_with_default_scheme;

    #[test]
    fn test_convert_idn_with_default_scheme() {
        assert!(
            convert_idn_with_default_scheme("example.com", "http")
                .unwrap()
                .eq_ignore_ascii_case("http://example.com")
        );
        assert!(
            convert_idn_with_default_scheme("http://example.com", "tcp")
                .unwrap()
                .eq_ignore_ascii_case("http://example.com")
        );
        assert!(
            convert_idn_with_default_scheme("example.com/1234", "http")
                .unwrap()
                .eq_ignore_ascii_case("http://example.com/1234")
        );
        assert!(
            convert_idn_with_default_scheme("http://example.com/1234", "tcp")
                .unwrap()
                .eq_ignore_ascii_case("http://example.com/1234")
        );
        assert!(
            convert_idn_with_default_scheme("example.com", "http")
                .unwrap()
                .eq_ignore_ascii_case("http://example.com")
        );
        // Repeating the stuff in the path to make sure the function doesn't touch it
        assert!(
            convert_idn_with_default_scheme("טעסט.إختبار/9999טעסט.إختبار", "ssh")
                .unwrap()
                .eq_ignore_ascii_case("ssh://XN--DEBA0AD.XN--KGBECHTV/9999טעסט.إختبار")
        );
        assert!(
            convert_idn_with_default_scheme("https://טעסט.إختبار/9999טעסט.إختبار", "ssh")
                .unwrap()
                .eq_ignore_ascii_case("https://XN--DEBA0AD.XN--KGBECHTV/9999טעסט.إختبار")
        );
    }
}
