use yumana_api_v2::utils::{generate_secure_token, hash_password, verify_password};

#[test]
fn test_password_hashing_and_verification() {
    let password = "mysecretpassword";
    let hash = hash_password(password).expect("Failed to hash password");
    
    assert_ne!(password, hash);
    assert!(verify_password(password, &hash).expect("Verification failed"));
    assert!(!verify_password("wrongpassword", &hash).expect("Verification failed"));
}

#[test]
fn test_generate_secure_token() {
    let t1 = generate_secure_token(32);
    let t2 = generate_secure_token(32);
    
    assert_eq!(t1.len(), 32); // Since we used UUID simple, it's 32 chars
    assert_ne!(t1, t2);
}
