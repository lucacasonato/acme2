error_chain! {
    types {
        Error, ErrorKind, ChainErr, Result;
    }

    links {
    }

    foreign_links {
        OpenSslErrorStack(openssl::error::ErrorStack);
        IoError(std::io::Error);
        HyperError(hyper::Error);
        ReqwestError(reqwest::Error);
        ValueParserError(serde_json::Error);
    }

    errors {
        AcmeServerError(resp: serde_json::Value) {
            description("Acme server error")
                display("Acme server error: {}", acme_server_error_description(resp))
        }
    }
}

fn acme_server_error_description(resp: &serde_json::Value) -> String {
    if let Some(obj) = resp.as_object() {
        let t = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let detail = obj.get("detail").and_then(|d| d.as_str()).unwrap_or("");
        format!("{} {}", t, detail)
    } else {
        String::new()
    }
}
