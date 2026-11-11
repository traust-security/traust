use actix_cors::Cors;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

fn ledger_routes() -> Router {
    // ruleid: traust-rust-cors-any-origin-with-credentials
    Router::new().layer(CorsLayer::very_permissive())
}

fn mirrored() -> CorsLayer {
    // ruleid: traust-rust-cors-any-origin-with-credentials
    CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_credentials(true)
}

fn listed() -> CorsLayer {
    // ok: traust-rust-cors-any-origin-with-credentials
    CorsLayer::new()
        .allow_origin("https://app.example.org".parse::<HeaderValue>().unwrap())
        .allow_credentials(true)
}

fn actix_cors() -> Cors {
    // ruleid: traust-rust-cors-any-origin-with-credentials
    Cors::permissive()
}

fn actix_listed() -> Cors {
    // ok: traust-rust-cors-any-origin-with-credentials
    Cors::default().allowed_origin("https://app.example.org").supports_credentials()
}
