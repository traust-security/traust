"""Legacy executor observation adapters; core owns every soundness decision."""

from __future__ import annotations

from pathlib import Path

from traust_core.v1.models.validation import ValidationObservations, ValidationProbe

INSTALL_FAILURE_FILENAME = "install-failure.yaml"


def _probe(verb: str, observed: str) -> ValidationProbe:
    return ValidationProbe(verdict="refuted", verb=verb, observed=observed)


def is_rbac_probe(verb: str, observed: str) -> bool:
    return _probe(verb, observed).is_rbac()


def match_error_signature(observed: str) -> str | None:
    return _probe("", observed).error_signature()


def soundness_flag(verb: str, observed: str, *, install_failure: bool = False) -> str | None:
    return (
        ValidationObservations(
            verdict="refuted",
            probes=(_probe(verb, observed),),
            install_failed=install_failure,
            controls_required=False,
            differential_required=False,
        )
        .soundness()
        .flag
    )


def gate_verdict(
    verdict: str, verb: str, observed: str, *, install_failure: bool = False
) -> tuple[str, str | None]:
    result = ValidationObservations(
        verdict=verdict,
        probes=(ValidationProbe(verdict=verdict, verb=verb, observed=observed),),
        install_failed=install_failure,
        controls_required=False,
        differential_required=False,
    ).soundness()
    return result.verdict.value, result.flag


def run_install_failed(run_dir: Path | str) -> bool:
    return (Path(run_dir) / INSTALL_FAILURE_FILENAME).is_file()


def _observations(
    vf: dict,
    *,
    install_failure: bool = False,
    controls_required: bool = False,
    differential_required: bool = False,
) -> ValidationObservations:
    return ValidationObservations(
        verdict=vf.get("verdict", "not_attempted"),
        probes=tuple(
            ValidationProbe(
                verdict=step.get("verdict", "not_attempted"),
                verb=step.get("verb") or "",
                observed="\n".join(
                    str(step[key]) for key in ("observed", "error") if step.get(key)
                ),
                positive_controls=tuple(control["ok"] for control in step.get("controls") or []),
                differential_discriminated=(step.get("differential") or {}).get("discriminated"),
            )
            for step in vf.get("steps") or []
        ),
        observed_impact=vf.get("observed_impact"),
        soundness_flag=vf.get("soundness_flag"),
        install_failed=install_failure,
        controls_required=controls_required,
        differential_required=differential_required,
    )


def controls_flag(vf: dict, *, required: bool = False) -> str | None:
    return _observations(vf, controls_required=required).controls_flag()


def differential_flag(vf: dict, *, required: bool = False) -> str | None:
    return _observations(vf, differential_required=required).differential_flag()


def flag_validated_finding(
    vf: dict,
    *,
    install_failure: bool = False,
    controls_required: bool = False,
    differential_required: bool = False,
) -> str | None:
    return (
        _observations(
            vf,
            install_failure=install_failure,
            controls_required=controls_required,
            differential_required=differential_required,
        )
        .soundness()
        .flag
    )
