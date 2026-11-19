"""A normal rig claim through the scheduled session commands. No external agent or forge."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from traust_core.v1.errors import ForbiddenError
from traust_core.v1.models.inventory import RefName
from traust_core.v1.models.operations import OrderRequest, PreflightRequest
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from tests.local_ops_support import REPO, LocalOpsRig
from traust.context import load, load_caller, load_recorder

# Only the paid executable is substituted: both generated reports pass through the normal CLI.
_AGENT = '''import json, os, shlex, subprocess, sys
from pathlib import Path
from uuid import UUID
sys.path.insert(0, os.environ['TEST_CHECKOUT'])
from scripts.ops_smoke.records import report
from traust.context import load, load_caller

def door(*args):
    done = subprocess.run([sys.executable, '-m', 'traust.cli', *args], capture_output=True, text=True)
    if done.returncode:
        raise RuntimeError(done.stderr)
    return json.loads(done.stdout)

fixture = Path(os.environ['TEST_INPUTS'])
core = load()
order = core.services().ops.get(UUID(os.environ['TRAUST_RUN_ID']))
assert order.lease_holder == load_caller(core).ref == 'machine:local-ops-recorder'
assert order.started_at.isoformat() == os.environ['TRAUST_ORDER_STARTED_AT']
words = shlex.split(sys.argv[-1])
if words[0] == '/secure-code-audit':
    authored = Path(os.environ['TEST_CHECKOUT']) / 'scripts/ops_smoke/authored.json'
    meta = json.loads(authored.read_text())['metadata']
    assert words == ['/secure-code-audit', meta['repository']]
    door('reporting', 'record', str(authored), '--kind', 'secure_code', '--repo-url', words[1],
         '--sha', meta['commit'], '--branch', meta['ref'])
else:
    skill, assessment, auto = words
    assert (skill, auto) == ('/triage', '--auto')
    prepared = door('triage', 'prepare', assessment)
    item, = prepared['items']
    path = fixture / 'result.json'
    path.write_bytes(report(item))
    receipt = door('triage', 'record', assessment, str(path), '--repo', str(fixture))
    (fixture / 'receipt.json').write_text(json.dumps(receipt))
print(json.dumps({'session_id':'local-fixture','modelUsage':{},'result':'fixture complete'}))
'''


def test_claim_runs_the_shipped_triage_command_as_its_own_recorder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip('traust_engine.ops.cli', reason='requires the candidate engine checkout')
    cosign = shutil.which('cosign')
    if not cosign:
        pytest.skip('requires cosign to verify the actual ledger signature')
    rig = LocalOpsRig(tmp_path)
    (rig.bin_dir / 'cosign').symlink_to(cosign)
    rig._executable(
        'traust-engine',
        f'#!{sys.executable}\nfrom traust_engine.ops.cli import main\nraise SystemExit(main())\n',
    )
    rig._executable('claude', f'#!{sys.executable}\n' + _AGENT)
    rig.env.update(TEST_CHECKOUT=str(REPO), TEST_INPUTS=str(tmp_path))
    setup = rig.run('up')
    assert setup.returncode == 0, setup.stderr
    run = rig.root / '.local-ops/run'
    token_file = run / 'recorder.token'
    assert token_file.stat().st_mode & 0o777 == 0o600
    monkeypatch.setenv('TRAUST_OPS_VALVE_SALT', (run / 'review-salt').read_text())
    monkeypatch.setenv('COSIGN_PASSWORD', '')
    # Use a disposable SQLite store instead of an external Postgres service.
    path = rig.config_home / 'traust.yaml'
    cfg = yaml.safe_load(path.read_text())
    del cfg['database']
    path.write_text(yaml.safe_dump(cfg))
    core = load(rig.config_home)
    human = load_caller(core)
    assert human.is_verified_human() and not core.config.recording.start
    with monkeypatch.context() as env:
        env.setenv('TRAUST_RECORDER_TOKEN_FILE', str(token_file))
        machine = load_recorder(core)
        assert machine.ref == 'machine:local-ops-recorder'
    svc = core.services()
    meta = json.loads((REPO / 'scripts/ops_smoke/authored.json').read_bytes())['metadata']
    (tmp_path / 'requirements.txt').write_text('fixture==1.0\n')
    url = HttpsRepoUrl.parse(meta['repository'], core.config.forge_hosts)
    repo = svc.portfolio.register_repository(url, False)
    svc.portfolio.mark_default_branch(repo.id, GitSha.parse(meta['commit']), RefName('main'))
    triage = OrderRequest(asset='sci_triage', repository_id=repo.id, priority=47)
    preflight = PreflightRequest(asset=triage.asset, repository_id=repo.id)
    with pytest.raises(ForbiddenError, match='ordering_violated'):
        svc.ops.preflight(preflight, human)
    with pytest.raises(ForbiddenError, match='role_denied'):
        svc.ops.submit(triage, machine)
    predecessor = svc.ops.plan(
        OrderRequest(asset='full_audit', repository_id=repo.id, priority=1), human
    )
    svc.ops.request_approval(predecessor.id)
    with pytest.raises(ForbiddenError):
        svc.ops.approve(predecessor.id, machine)
    approved = rig.run('approve', str(predecessor.id))
    assert approved.returncode == 0, approved.stderr

    # Limit the test's inventory of executables; retain the exact scheduled command, model,
    # label and triage prerequisite. Never start the normal pack's other sessions or feeds.
    pack = rig.root / '.local-ops/pack/assets.yaml'
    assets = yaml.safe_load(pack.read_text())['assets']
    assets['full_audit'].pop('deps')
    selected = {name: assets[name] for name in ('full_audit', 'sci_triage', 'ledger_audit')}
    pack.write_text(yaml.safe_dump({'pack': 'fixture', 'approvers': ['operators'], 'assets': selected}))
    audit = rig.run('claim', '--once', timeout=120)
    assert audit.returncode == 0, audit.stderr + audit.stdout
    (baseline,) = svc.assessment.list_for_order(predecessor.id)
    assert baseline.kind == 'secure_code' and svc.ops.preflight(preflight, human).allowed
    with pytest.raises(ForbiddenError, match='role_denied'):
        svc.ops.submit(triage, machine)
    order = svc.ops.submit(triage, human)
    claimed = rig.run('claim', '--once', timeout=120)
    assert claimed.returncode == 0, claimed.stderr + claimed.stdout
    assert svc.ops.get(order.id).state == 'succeeded'
    receipt = json.loads((tmp_path / 'receipt.json').read_bytes())
    assert UUID(receipt['baseline_assessment_id']) == baseline.id
    (native,) = svc.assessment.list_for_order(order.id)
    assert native.kind == 'triage' and native.baseline_assessment_id == baseline.id
    (record,) = receipt['records']
    assert UUID(record['assessment_id']) == native.id and receipt['decisions'] == 1
    (proof,) = svc.ledger.audit()
    assert proof.passed and svc.ledger.layer(proof.layer_id).merkle_root_signature
    unrelated = svc.ops.submit(OrderRequest(asset='ledger_audit', priority=50), human)
    last = rig.run('claim', '--once', timeout=120)
    assert last.returncode == 0 and svc.ops.get(unrelated.id).state == 'succeeded', last.stderr
    assert load_caller(core) == human
    for secret in (token_file.read_text(), (run / 'review-salt').read_text()):
        for command in (setup, approved, audit, claimed, last):
            assert secret not in command.stdout + command.stderr
