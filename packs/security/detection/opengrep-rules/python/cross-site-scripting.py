from django.utils.html import conditional_escape, escape, format_html
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


def formatted_greeting(request):
    fmt = request.POST.get("layout")
    # A safe argument does not make an attacker-controlled format string safe.
    # ruleid: traust-python-xss-mark-safe-taint
    return format_html(fmt, "visitor")


def escaped_badge(request):
    nickname = request.GET.get("nick")
    # ok: traust-python-xss-mark-safe-taint
    first = mark_safe("<b>%s</b>" % conditional_escape(nickname))
    # ok: traust-python-xss-mark-safe-taint
    second = mark_safe("<b>%s</b>" % escape(nickname))
    # ok: traust-python-xss-mark-safe-taint
    third = mark_safe(format_html("<b>{}</b>", nickname))
    return first, second, third
