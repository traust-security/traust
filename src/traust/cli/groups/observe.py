"""``traust observe …`` — collect facts for later routing."""

from traust.cli.groups._registry import OpSpec, passthrough_op


def _add_args(parser):
    from traust.cli.observe_repo_state import add_args

    add_args(parser)


_handler = passthrough_op("observe_repo_state", "Observe and store one repository's state.")

OBSERVE = {
    "repo-state": OpSpec(
        add_args=_add_args,
        call=_handler.call,
        help=_handler.help,
        passthrough_argv=True,
    ),
}
