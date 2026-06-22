use yumana_api_v2::AppEnv;

#[test]
fn test_app_env_display() {
    assert_eq!(AppEnv::Debug.to_string(), "debug");
    assert_eq!(AppEnv::Release.to_string(), "release");
}
