use axum::response::IntoResponse;
use yumana_api_v2::utils::ui::render_verify_result;

#[tokio::test]
async fn test_render_verify_result_success() {
    let response = render_verify_result(
        "Sukses",
        "Pesan sukses",
        true,
        "http://action.com",
        "Tombol",
    )
    .into_response();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), 10000)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("Sukses"));
    assert!(html.contains("Pesan sukses"));
    assert!(html.contains("http://action.com"));
    assert!(html.contains("icon-success"));
}

#[tokio::test]
async fn test_render_verify_result_error() {
    let response =
        render_verify_result("Gagal", "Pesan error", false, "http://retry.com", "Ulangi")
            .into_response();

    assert_eq!(response.status(), 200); // UI helper returns 200 for the result page itself

    let body = axum::body::to_bytes(response.into_body(), 10000)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();

    assert!(html.contains("Gagal"));
    assert!(html.contains("Pesan error"));
    assert!(html.contains("icon-error"));
}
