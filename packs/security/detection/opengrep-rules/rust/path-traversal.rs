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

fn save_content(req: &StoreFileRequest) -> Result<()> {
    // Request-controlled content is not a request-controlled destination.
    // ok: traust-rust-path-traversal-request-taint
    fs::write("/srv/uploads/current.bin", &req.content)?;
    Ok(())
}

async fn sanitized_upload(Path(name): Path<String>) -> Vec<u8> {
    let only = sanitize_filename::sanitize(&name);
    // Assumes a trusted upload directory; sanitizer matching does not prove
    // authorization, symlink safety, or freedom from overwrite collisions.
    // ok: traust-rust-path-traversal-request-taint
    std::fs::read(PathBuf::from(UPLOADS).join(only)).unwrap_or_default()
}

fn destination_paths(req: &StoreFileRequest) -> Result<()> {
    // Both operands of each operation are paths, including constant sources
    // copied, renamed, or linked into a request-controlled destination.
    // ruleid: traust-rust-path-traversal-request-taint
    fs::copy("/srv/template", &req.name)?;
    // ruleid: traust-rust-path-traversal-request-taint
    fs::rename("/srv/staged", &req.name)?;
    // ruleid: traust-rust-path-traversal-request-taint
    fs::hard_link("/srv/template", &req.name)?;
    // ruleid: traust-rust-path-traversal-request-taint
    std::fs::copy("/srv/template", &req.name)?;
    // ruleid: traust-rust-path-traversal-request-taint
    std::fs::rename("/srv/staged", &req.name)?;
    // ruleid: traust-rust-path-traversal-request-taint
    std::fs::hard_link("/srv/template", &req.name)?;
    Ok(())
}

async fn async_destination_paths(req: &StoreFileRequest) -> Result<()> {
    // ruleid: traust-rust-path-traversal-request-taint
    tokio::fs::copy("/srv/template", &req.name).await?;
    // ruleid: traust-rust-path-traversal-request-taint
    tokio::fs::rename("/srv/staged", &req.name).await?;
    // ruleid: traust-rust-path-traversal-request-taint
    tokio::fs::hard_link("/srv/template", &req.name).await?;
    Ok(())
}

fn source_paths(req: &StoreFileRequest) -> Result<()> {
    // Fixing destination detection must preserve source-path detection.
    // ruleid: traust-rust-path-traversal-request-taint
    fs::copy(&req.name, "/srv/copy")?;
    // ruleid: traust-rust-path-traversal-request-taint
    std::fs::rename(&req.name, "/srv/moved")?;
    // ruleid: traust-rust-path-traversal-request-taint
    tokio::fs::hard_link(&req.name, "/srv/link");
    Ok(())
}

async fn non_path_arguments(req: &StoreFileRequest) -> Result<()> {
    // ok: traust-rust-path-traversal-request-taint
    std::fs::write("/srv/uploads/current.bin", &req.content)?;
    // ok: traust-rust-path-traversal-request-taint
    tokio::fs::write("/srv/uploads/current.bin", &req.content).await?;
    // Request-derived permission bits do not select the filesystem path.
    // ok: traust-rust-path-traversal-request-taint
    fs::set_permissions("/srv/uploads/current.bin", req.permissions)?;
    // ok: traust-rust-path-traversal-request-taint
    std::fs::set_permissions("/srv/uploads/current.bin", req.permissions)?;
    // ok: traust-rust-path-traversal-request-taint
    tokio::fs::set_permissions("/srv/uploads/current.bin", req.permissions).await?;
    // ok: traust-rust-path-traversal-request-taint
    fs::copy("/srv/template", "/srv/uploads/copy")?;
    // ok: traust-rust-path-traversal-request-taint
    std::fs::rename("/srv/staged", "/srv/uploads/moved")?;
    // ok: traust-rust-path-traversal-request-taint
    tokio::fs::hard_link("/srv/template", "/srv/uploads/link").await?;
    Ok(())
}

fn sanitized_destination(req: &StoreFileRequest) -> Result<()> {
    let name = sanitize_filename::sanitize(&req.name);
    // Assumes the same trusted-directory policy as sanitized_upload.
    // ok: traust-rust-path-traversal-request-taint
    fs::copy("/srv/template", PathBuf::from(UPLOADS).join(name))?;
    Ok(())
}
