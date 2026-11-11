from django.utils.html import format_html
from django.utils.safestring import mark_safe


def profile_badge(request):
    nickname = request.GET.get("nick")
    # ruleid: traust-python-xss-mark-safe-taint
    return mark_safe("<b>%s</b>" % nickname)


def greeting(request):
    fmt = request.POST.get("layout")
    # ruleid: traust-python-xss-mark-safe-taint
    return format_html(fmt)


def safe_usage(request):
    nickname = request.GET.get("nick")
    # ok: traust-python-xss-mark-safe-taint
    return format_html("<b>{}</b>", nickname)


def static_markup():
    # ok: traust-python-xss-mark-safe-taint
    return mark_safe("<hr>")
