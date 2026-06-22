use yumana_api_v2::validation::{validate_email, validate_length};

#[test]
fn test_validate_email_success() {
    assert!(validate_email("test@example.com").is_ok());
    assert!(validate_email("user.name+tag@domain.co.id").is_ok());
}

#[test]
fn test_validate_email_failure() {
    assert!(validate_email("").is_err());
    assert!(validate_email("invalid-email").is_err());
    assert!(validate_email("@domain.com").is_err());
    assert!(validate_email("user@").is_err());
}

#[test]
fn test_validate_length_success() {
    assert!(validate_length("Username", "abc", 3, 5).is_ok());
    assert!(validate_length("Username", "abcde", 3, 5).is_ok());
}

#[test]
fn test_validate_length_failure() {
    assert!(validate_length("Username", "ab", 3, 5).is_err());
    assert!(validate_length("Username", "abcdef", 3, 5).is_err());
}
