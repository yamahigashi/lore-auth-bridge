mod support;

#[test]
fn redact_lore_args_hides_token_value() {
    if !support::require_e2e() {
        return;
    }

    let args = support::redact_lore_args(&[
        "auth",
        "login",
        "--token-type",
        "lore",
        "--token",
        "header.payload.signature",
        "--auth-url",
        "https://localhost:8081",
    ]);

    let joined = args.join(" ");
    assert!(
        !joined.contains("header.payload.signature"),
        "redacted args leaked token: {joined}"
    );
    assert!(
        joined.contains("<redacted>"),
        "redacted args missing marker: {joined}"
    );
}
