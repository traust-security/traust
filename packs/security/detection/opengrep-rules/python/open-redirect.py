from flask import redirect, request


@app.route("/login/done")
def done():
    target = request.args.get("next")
    # ruleid: traust-python-open-redirect-taint
    return redirect(target)


def django_done(request):
    # ruleid: traust-python-open-redirect-taint
    return HttpResponseRedirect(request.GET.get("return_to"))


async def star_done(request):
    # ruleid: traust-python-open-redirect-taint
    return RedirectResponse(request.query_params["next"])


@app.route("/logout")
def logout():
    # ok: traust-python-open-redirect-taint
    return redirect("/")


def safe_done(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        # ok: traust-python-open-redirect-taint
        return HttpResponseRedirect("/home")


def legacy_search(request):
    search_url = reverse("search")
    q = request.GET.get("q")
    search_url += "?q=%s" % q
    # ok: traust-python-open-redirect-taint
    return redirect(search_url)

