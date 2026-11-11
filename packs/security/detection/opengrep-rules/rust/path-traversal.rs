use std::fs::{self, File};
use std::path::PathBuf;

fn save_upload(req: &StoreFileRequest) -> Result<()> {
    let path = PathBuf::from(req.name.as_str());
    // ruleid: traust-rust-path-traversal-request-taint
    fs::write(&path, &req.content)?;
    Ok(())
}

async fn read_doc(&self, request: Request<ReadDocRequest>) -> Result<Response<Doc>, Status> {
    let doc = request.into_inner();
    let file_path = Url::parse(&doc.location)?.to_file_path()?;
    // ruleid: traust-rust-path-traversal-request-taint
    let file = File::open(&file_path)?;
    Ok(Response::new(Doc::default()))
}

async fn upload(Path(name): Path<String>) -> Vec<u8> {
    // ruleid: traust-rust-path-traversal-request-taint
    tokio::fs::read(PathBuf::from(UPLOADS).join(name)).await.unwrap_or_default()
}

async fn safe(Path(name): Path<String>) -> Vec<u8> {
    let only = PathBuf::from(&name).file_name().unwrap().to_owned();
    // ok: traust-rust-path-traversal-request-taint
    std::fs::read(PathBuf::from(UPLOADS).join(only)).unwrap_or_default()
}

fn load_default() -> Vec<u8> {
    // ok: traust-rust-path-traversal-request-taint
    std::fs::read("/etc/collector/defaults.toml").unwrap_or_default()
}
