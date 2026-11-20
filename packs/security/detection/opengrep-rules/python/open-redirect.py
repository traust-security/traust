from flask import redirect, request
from urllib.parse import quote


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
        return HttpResponseRedirect(nxt)


def legacy_search(request):
    search_url = reverse("search")
    q = request.GET.get("q")
    search_url += "?q=%s" % q
    # ok: traust-python-open-redirect-taint
    return redirect(search_url)


def unchecked_done(request):
    nxt = request.GET.get("next")
    url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()})
    # ruleid: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def quoted_done(request):
    # quote() preserves slashes by default: //other.example remains external.
    # ruleid: traust-python-open-redirect-taint
    return redirect(quote(request.GET.get("next")))


def keyword_checked(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(url=nxt, allowed_hosts={request.get_host()}):
        # ok: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def positional_checked(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, {request.get_host()}, True):
        # ok: traust-python-open-redirect-taint
        return RedirectResponse(url=nxt)


def legacy_keyword_checked(request):
    nxt = request.GET.get("next")
    if is_safe_url(url=nxt, allowed_hosts={request.get_host()}):
        # ok: traust-python-open-redirect-taint
        return redirect(nxt)


def legacy_positional_checked(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, {request.get_host()}):
        # ok: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def early_return_checked(request):
    nxt = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(url=nxt, allowed_hosts={request.get_host()}):
        return HttpResponseRedirect("/")
    # ok: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def legacy_early_return_checked(request):
    nxt = request.GET.get("next")
    if not is_safe_url(nxt, {request.get_host()}):
        return redirect("/")
    # ok: traust-python-open-redirect-taint
    return RedirectResponse(url=nxt)


def stored_checked(request):
    nxt = request.GET.get("next")
    valid = url_has_allowed_host_and_scheme(url=nxt, allowed_hosts={request.get_host()})
    if valid:
        # ok: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def legacy_stored_checked(request):
    nxt = request.GET.get("next")
    valid = is_safe_url(nxt, {request.get_host()})
    if valid:
        # ok: traust-python-open-redirect-taint
        return RedirectResponse(url=nxt)


def stored_early_return_checked(request):
    nxt = request.GET.get("next")
    valid = url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()})
    if not valid:
        return redirect("/")
    # ok: traust-python-open-redirect-taint
    return redirect(nxt)


def legacy_stored_early_return_checked(request):
    nxt = request.GET.get("next")
    valid = is_safe_url(url=nxt, allowed_hosts={request.get_host()})
    if not valid:
        return redirect("/")
    # ok: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def changed_in_safe_branch(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        nxt = request.GET.get("override")
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def changed_after_early_guard(request):
    nxt = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        return redirect("/")
    nxt = request.GET.get("override")
    # ruleid: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def changed_before_stored_branch(request):
    nxt = request.GET.get("next")
    valid = url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()})
    nxt = request.GET.get("override")
    if valid:
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def changed_in_stored_branch(request):
    nxt = request.GET.get("next")
    valid = is_safe_url(nxt, {request.get_host()})
    if valid:
        nxt = request.GET.get("override")
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def overwritten_validation_result(request):
    nxt = request.GET.get("next")
    valid = url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()})
    valid = True
    if valid:
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def rejected_branch(request):
    nxt = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(url=nxt, allowed_hosts={request.get_host()}):
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def rejected_stored_branch(request):
    nxt = request.GET.get("next")
    valid = is_safe_url(nxt, {request.get_host()})
    if not valid:
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def rejected_else_branch(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        # ok: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)
    else:
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def redirects_in_both_branches(request):
    nxt = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}):
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)
    # ok: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def validation_is_not_required(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}) or request.GET.get("override"):
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def validates_different_url(request):
    nxt = request.GET.get("next")
    if is_safe_url("/", allowed_hosts={request.get_host()}):
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def bare_early_return_checked(request):
    nxt = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(nxt, {request.get_host()}):
        return
    # ok: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def unchecked_keyword_validator(request):
    nxt = request.GET.get("next")
    is_safe_url(url=nxt, allowed_hosts={request.get_host()})
    # ruleid: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def explicitly_rejected_branch(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}) is False:
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def changed_in_early_guard_else(request):
    nxt = request.GET.get("next")
    if not url_has_allowed_host_and_scheme(nxt, {request.get_host()}):
        return redirect("/")
    else:
        nxt = request.GET.get("override")
    # ruleid: traust-python-open-redirect-taint
    return HttpResponseRedirect(nxt)


def changed_in_stored_guard_else(request):
    nxt = request.GET.get("next")
    valid = is_safe_url(url=nxt, allowed_hosts={request.get_host()})
    if not valid:
        return redirect("/")
    else:
        nxt = request.GET.get("override")
    # ruleid: traust-python-open-redirect-taint
    return RedirectResponse(url=nxt)


def attacker_supplies_allowed_host(request):
    nxt = request.GET.get("next")
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.GET.get("host")}):
        # ruleid: traust-python-open-redirect-taint
        return redirect(nxt)


def attacker_host_policy_alias(request):
    nxt = request.GET.get("next")
    hosts = {request.GET.get("host")}
    valid = url_has_allowed_host_and_scheme(url=nxt, allowed_hosts=hosts)
    if valid:
        # ruleid: traust-python-open-redirect-taint
        return HttpResponseRedirect(nxt)


def attacker_host_early_guard(request):
    nxt = request.GET.get("next")
    hosts = {request.GET.get("host")}
    if not is_safe_url(nxt, hosts):
        return redirect("/")
    # ruleid: traust-python-open-redirect-taint
    return RedirectResponse(url=nxt)


def mixed_untrusted_host_policy(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts={"trusted.example", request.GET.get("host")}):
        # ruleid: traust-python-open-redirect-taint
        return redirect(nxt)


def unpacked_untrusted_host_policy(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts={"trusted.example", *request.GET.getlist("host")}):
        # ruleid: traust-python-open-redirect-taint
        return redirect(nxt)


def destination_chooses_its_own_policy(request):
    from urllib.parse import urlparse
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts={urlparse(nxt).hostname}):
        # ruleid: traust-python-open-redirect-taint
        return redirect(nxt)


def trusted_literal_host_policies(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts={"trusted.example", "login.example"}):
        # ok: traust-python-open-redirect-taint
        return redirect(nxt)


def trusted_literal_host_list(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts=["trusted.example", "login.example"]):
        # ok: traust-python-open-redirect-taint
        return redirect(nxt)


def trusted_literal_host_tuple(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts=("trusted.example", "login.example")):
        # ok: traust-python-open-redirect-taint
        return redirect(nxt)


def trusted_literal_host_string(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts="trusted.example"):
        # ok: traust-python-open-redirect-taint
        return redirect(nxt)


def trusted_current_and_static_hosts(request):
    nxt = request.GET.get("next")
    if is_safe_url(nxt, allowed_hosts={request.get_host(), "trusted.example"}):
        # ok: traust-python-open-redirect-taint
        return redirect(nxt)
