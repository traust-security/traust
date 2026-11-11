import os
import subprocess

from flask import request


def run_dynamic(user_target):
    # ruleid: traust-python-injection-subprocess-shell
    subprocess.run(f"nslookup {user_target}", shell=True)

    # ruleid: traust-python-injection-subprocess-shell
    os.system("ping -c1 " + user_target)

    # ok: traust-python-injection-subprocess-shell
    subprocess.run("systemctl restart chronyd", shell=True)

    # ok: traust-python-injection-subprocess-shell
    subprocess.run(["nslookup", user_target])


def handler():
    host = request.args.get("host")
    # ruleid: traust-python-injection-request-to-shell-taint
    subprocess.check_output(["dig", host])

    # ok: traust-python-injection-request-to-shell-taint
    subprocess.check_output(["dig", "example.com"])


def raw_sql(request, connection, Model):
    q = request.GET.get("q")
    cursor = connection.cursor()
    # ruleid: traust-python-injection-raw-sql-taint
    cursor.execute("SELECT * FROM t WHERE name = '%s'" % q)

    # ruleid: traust-python-injection-raw-sql-taint
    Model.objects.extra(where=["name = '%s'" % q])

    # ok: traust-python-injection-raw-sql-taint
    cursor.execute("SELECT * FROM t WHERE fixed = 1")


def render_user_template(request):
    import jinja2
    tpl = request.form.get("template")
    # ruleid: traust-python-injection-jinja2-template-taint
    return jinja2.Template(tpl).render()


def render_static_template():
    import jinja2
    # ok: traust-python-injection-jinja2-template-taint
    return jinja2.Template("hello {{ name }}").render(name="world")


def owned_items_orm(Item, owner_name, session):
    # ruleid: traust-python-injection-like-wildcard-unescaped
    session.query(Item).filter(Item.name.like(owner_name + "+%"))

    # ruleid: traust-python-injection-like-wildcard-unescaped
    session.query(Item).filter(Item.name.ilike(f"{owner_name}/%"))

    # ruleid: traust-python-injection-like-wildcard-unescaped
    Item.select().where(Item.name ** (owner_name + "+%"))

    # ruleid: traust-python-injection-like-wildcard-unescaped
    Item.select().where(Item.name ** "{}+%".format(owner_name))

    # ok: traust-python-injection-like-wildcard-unescaped
    session.query(Item).filter(Item.name.like(escape_like(owner_name) + "+%", escape="\\"))

    # ok: traust-python-injection-like-wildcard-unescaped
    Item.select().where(Item.name ** (escape_wildcards(owner_name) + "+%"))

    # ok: traust-python-injection-like-wildcard-unescaped
    session.query(Item).filter(Item.owner_id == owner_name)

    # ok: traust-python-injection-like-wildcard-unescaped
    session.query(Item).filter(Item.name.like("fixed-prefix-%"))

    # ok: traust-python-injection-like-wildcard-unescaped
    total = base ** exponent
    return total


def owned_items_sql(cursor, owner_name, folder):
    # ruleid: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE name LIKE '" + owner_name + "+%'")

    # ruleid: traust-python-injection-like-wildcard-unescaped
    cursor.execute(f"SELECT id FROM item WHERE name ILIKE '{owner_name}%'")

    # ruleid: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE name LIKE %s", (owner_name + "%",))

    # ok: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE name LIKE %s ESCAPE '\\'", (escape_like(owner_name) + "%",))

    # ruleid: traust-python-injection-like-wildcard-unescaped
    cursor.execute("DELETE FROM item WHERE path LIKE ?", (f"{owner_name}/{folder}/%",))

    # ruleid: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE path LIKE %s", [f"%{owner_name}/{folder}"])

    # ok: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE path LIKE ?", (f"{owner_name}/{folder}",))

    # ok: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE name = %s", (owner_name,))

    # ok: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE name LIKE %s", (owner_name,))

    # ok: traust-python-injection-like-wildcard-unescaped
    cursor.execute("SELECT id FROM item WHERE owner = '" + owner_name + "'")

    # ok: traust-python-injection-like-wildcard-unescaped
    cursor.execute(f"CREATE TABLE tmp_{owner_name} (LIKE base_{owner_name} INCLUDING ALL)")

    # ok: traust-python-injection-like-wildcard-unescaped
    cursor.execute(f"CREATE TABLE {owner_name}_copy (LIKE {owner_name} INCLUDING DEFAULTS)")
