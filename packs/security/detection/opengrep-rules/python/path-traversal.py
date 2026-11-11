import os
import tarfile
import zipfile


def unpack(archive_path, dest):
    tar = tarfile.open(archive_path)
    # ruleid: traust-python-path-traversal-tar-extractall-nofilter
    tar.extractall(dest)

    member = tar.getmembers()[0]
    # ruleid: traust-python-path-traversal-tar-extractall-nofilter
    tar.extract(member, dest)

    # ok: traust-python-path-traversal-tar-extractall-nofilter
    tar.extractall(dest, filter="data")

    # ok: traust-python-path-traversal-tar-extractall-nofilter
    tar.extract(member, dest, filter="data")


def unpack_zip(archive_path, dest):
    # zipfile sanitizes member paths on extract — zip-slip is tarfile-only;
    # flagging these re-seeds a refuted FP class (Precision Gate R9).
    zf = zipfile.ZipFile(archive_path)
    # ok: traust-python-path-traversal-tar-extractall-nofilter
    zf.extractall(dest)

    with zipfile.ZipFile(archive_path) as zf2:
        # ok: traust-python-path-traversal-tar-extractall-nofilter
        zf2.extractall(dest)


def contained(base, name):
    p = os.path.join(base, name)
    # ruleid: traust-python-path-traversal-containment-startswith
    if os.path.realpath(p).startswith(base):
        return p

    # ruleid: traust-python-path-traversal-containment-startswith
    if os.path.abspath(p).startswith(base):
        return p

    # ok: traust-python-path-traversal-containment-startswith
    if os.path.realpath(p).startswith(base + os.sep):
        return p

    # ok: traust-python-path-traversal-containment-startswith
    if os.path.abspath(p).startswith(os.path.join(base, "")):
        return p
    return None


@router.get("/files/{path_name:path}")
async def serve_file(path_name: str):
    file_path = DATA_DIR / path_name
    # ruleid: traust-python-path-traversal-file-response-taint
    return FileResponse(file_path)


@api.custom_route("/assets/{asset:path}", methods=["GET"])
async def assets(request: Request) -> FileResponse:
    target = ASSET_ROOT / request.path_params["asset"]
    # ruleid: traust-python-path-traversal-file-response-taint
    return FileResponse(target)


@router.api_route("/pages/{page:path}", methods=["GET"], response_class=FileResponse)
async def page(page: str):
    found = PAGE_ROOT / f"{page}.md"
    if found.exists():
        # ruleid: traust-python-path-traversal-file-response-taint
        return found


@router.get("/docs/{name:path}")
async def doc(name: str):
    # ruleid: traust-python-path-traversal-file-response-taint
    with open(os.path.join(DOCS, name)) as fh:
        return fh.read()


@router.get("/safe/{name:path}")
async def safe(name: str):
    # ok: traust-python-path-traversal-file-response-taint
    return FileResponse(DATA_DIR / os.path.basename(name))


@router.get("/report/{report_id}")
async def report(report_id: str):
    # ok: traust-python-path-traversal-file-response-taint
    return FileResponse(REPORTS / "summary.pdf")
