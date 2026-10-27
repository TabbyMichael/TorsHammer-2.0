//! Target URL parsing (stdlib only).
//!
//! Accepts `http://host[:port][/path]`, `udp://host[:port]`, bare
//! `host[:port][/path]`, and bracketed IPv6 literals. `https://` is
//! recognized by the parser but the Rust engine currently refuses TLS
//! targets (would need external dependencies).

/// A parsed target with the pieces the engine needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// URL scheme, lower-cased (`http` or `https`).
    pub scheme: String,
    /// Host without brackets (IPv6 literals are unbracketed here).
    pub host: String,
    pub port: u16,
    /// Request path (always starts with `/`).
    pub path: String,
    /// RFC 7230 `Host` header value (IPv6 literals are bracketed).
    pub header_host: String,
}

/// Parse a target string into the fields the engine needs.
pub fn parse(raw: &str) -> Result<Target, String> {
    let input = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    // Both branches above guarantee a `://` separator is present, so the split
    // can never fail; `expect` documents that invariant without leaving an
    // unreachable error-formatter closure behind.
    let (scheme, rest) = input
        .split_once("://")
        .expect("normalized target always contains a scheme separator");
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" && scheme != "udp" {
        return Err(format!(
            "unsupported URL scheme {scheme:?} (only http/https/udp)"
        ));
    }

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(format!("target URL has no host: {raw}"));
    }

    let default = default_port(&scheme);
    let (host, port) = if authority.starts_with('[') {
        // [::1]:8080 style literal
        let close = authority
            .find(']')
            .ok_or_else(|| format!("malformed IPv6 literal in target: {raw}"))?;
        let host = authority[1..close].to_string();
        let after = &authority[close + 1..];
        let port = if after.is_empty() {
            default
        } else {
            after
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .ok_or_else(|| format!("invalid port in target URL: {raw}"))?
        };
        (host, port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("invalid port in target URL: {raw}"));
        }
        let port = p
            .parse::<u16>()
            .map_err(|_| format!("invalid port in target URL: {raw}"))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), default)
    };

    if host.is_empty() {
        return Err(format!("target URL has no host: {raw}"));
    }

    let bb = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let header_host = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        bb
    } else {
        format!("{bb}:{port}")
    };

    Ok(Target {
        scheme,
        host,
        port,
        path,
        header_host,
    })
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else if scheme == "udp" {
        53
    } else {
        80
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_url_is_parsed() {
        let t = parse("http://example.com:8080/api").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 8080);
        assert_eq!(t.path, "/api");
        assert_eq!(t.header_host, "example.com:8080");
    }

    #[test]
    fn default_port_is_omitted_from_host_header() {
        let t = parse("http://example.com/").unwrap();
        assert_eq!(t.port, 80);
        assert_eq!(t.header_host, "example.com");
        assert_eq!(t.path, "/");
    }

    #[test]
    fn bare_host_gets_http_scheme() {
        let t = parse("127.0.0.1:9000").unwrap();
        assert_eq!(t.scheme, "http");
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 9000);
    }

    #[test]
    fn ipv6_literal_gets_bracketed_host_header() {
        let t = parse("http://[::1]:8080/x").unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 8080);
        assert_eq!(t.header_host, "[::1]:8080");
        assert_eq!(t.path, "/x");
    }

    #[test]
    fn ipv6_default_port_host_header_is_still_bracketed() {
        let t = parse("http://[::1]/").unwrap();
        assert_eq!(t.port, 80);
        assert_eq!(t.header_host, "[::1]");
    }

    #[test]
    fn https_is_recognized() {
        let t = parse("https://example.com").unwrap();
        assert_eq!(t.scheme, "https");
        assert_eq!(t.port, 443);
        assert_eq!(t.header_host, "example.com");
    }

    #[test]
    fn udp_scheme_is_parsed() {
        let t = parse("udp://127.0.0.1:9000").unwrap();
        assert_eq!(t.scheme, "udp");
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 9000);
    }

    #[test]
    fn udp_default_port_is_53() {
        let t = parse("udp://example.com").unwrap();
        assert_eq!(t.scheme, "udp");
        assert_eq!(t.port, 53);
    }

    #[test]
    fn invalid_inputs_error() {
        assert!(parse("ftp://example.com").is_err());
        assert!(parse("http://").is_err());
        assert!(parse("http://example.com:notaport").is_err());
    }

    #[test]
    fn out_of_range_port_errors() {
        // `:99999` is all digits but overflows u16, so the `parse::<u16>`
        // failure path (url.rs L68-70) must surface an error.
        assert!(parse("http://example.com:99999").is_err());
    }

    #[test]
    fn malformed_ipv6_literal_errors() {
        // A bracketed literal missing its closing `]` (url.rs L50-52).
        assert!(parse("http://[::1/").is_err());
    }

    #[test]
    fn ipv6_invalid_port_errors() {
        // A non-numeric port after a valid IPv6 literal (url.rs L58-61).
        assert!(parse("http://[::1]:bad").is_err());
    }

    #[test]
    fn empty_host_before_port_errors() {
        // A leading colon yields an empty host after port parsing (url.rs L76-77).
        assert!(parse("http://:8080/").is_err());
        assert!(parse("http://:/").is_err());
    }
}
