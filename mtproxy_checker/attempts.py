from __future__ import annotations

from .errors import UnsupportedModeError
from .models import Mode, ParsedSecret
from .parser import DEFAULT_DCS, DEFAULT_FAST_DCS


def normalize_mode(mode: Mode | str) -> Mode | str:
    if isinstance(mode, Mode):
        return mode

    if mode == "auto":
        return "auto"

    try:
        return Mode(mode)
    except ValueError as exc:
        raise UnsupportedModeError(f"unsupported mode: {mode}") from exc


def build_attempts(
    secret: ParsedSecret,
    requested_mode: Mode | str,
    dc: int | None,
    dcs: tuple[int, ...] | None,
    exhaustive: bool,
) -> tuple[tuple[int, Mode], ...]:
    normalized_mode = normalize_mode(requested_mode)

    if secret.is_faketls:
        if normalized_mode not in ("auto", Mode.FAKETLS):
            raise UnsupportedModeError(
                "FakeTLS secret cannot be checked with non-FakeTLS mode"
            )

        selected_modes: tuple[Mode, ...] = (Mode.FAKETLS,)
    elif normalized_mode == Mode.FAKETLS:
        raise UnsupportedModeError("FakeTLS mode requires an EE/FakeTLS secret")
    elif normalized_mode != "auto":
        assert isinstance(normalized_mode, Mode)
        selected_modes = (normalized_mode,)
    elif exhaustive:
        selected_modes = (Mode.SECURE, Mode.ABRIDGED, Mode.INTERMEDIATE)
    else:
        selected_modes = (Mode.SECURE,)

    if dc is not None:
        selected_dcs: tuple[int, ...] = (dc,)
    elif dcs is not None:
        selected_dcs = dcs
    elif exhaustive:
        selected_dcs = DEFAULT_DCS
    else:
        selected_dcs = DEFAULT_FAST_DCS

    return tuple((dc_id, mode) for dc_id in selected_dcs for mode in selected_modes)


def describe_secret(secret: ParsedSecret) -> str:
    if secret.is_faketls:
        return f"faketls domain={secret.faketls_domain!r}"

    return secret.kind.value


def format_attempts(attempts: tuple[tuple[int, Mode], ...]) -> str:
    return ",".join(f"dc={dc_id}/{mode.value}" for dc_id, mode in attempts)


def effective_inner_mode(mode: Mode) -> Mode:
    if mode == Mode.FAKETLS:
        return Mode.SECURE

    return mode
