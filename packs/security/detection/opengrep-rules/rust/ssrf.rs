use axum::extract::Query;

async fn preview(Query(params): Query<PreviewParams>) -> String {
    // ruleid: traust-rust-ssrf-request-taint
    let body = reqwest::get(&params.url).await.unwrap().text().await.unwrap();
    body
}

async fn relay(&self, request: Request<RelayRequest>) -> Result<Response<Ack>, Status> {
    let msg = request.into_inner();
    let client = reqwest::Client::new();
    // ruleid: traust-rust-ssrf-request-taint
    client.get(&msg.callback).send().await.ok();
    Ok(Response::new(Ack::default()))
}

async fn status() -> String {
    // ok: traust-rust-ssrf-request-taint
    reqwest::get("https://status.example.com/health").await.unwrap().text().await.unwrap()
}

async fn lookup(Path(key): Path<String>, db: &HashMap<String, String>) -> String {
    // ok: traust-rust-ssrf-request-taint
    db.get(&key).cloned().unwrap_or_default()
}

