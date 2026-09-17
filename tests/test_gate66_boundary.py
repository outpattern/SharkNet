"""
Gate 6.6 — production vs test-oracle boundary.

ScapyCapture/ScapyInjector are retained ONLY as the equivalence oracle for
test_stage1_io + test_stage23_equivalence. These tests are the guardrail proving
they can never re-enter the production runtime:
  * iobackend hands out ONLY the native backend,
  * no env var can flip production to the scapy oracle,
  * no production module imports the oracle classes.
(The scapy-absent full-app import proof lives in test_gate64_scapy_removal.py.)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.engine import iobackend                                  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(REPO, "backend")


def test_iobackend_hands_out_native_only():
    from backend.engine.npcap import NpcapCapture
    assert iobackend.active_backend() == "native"
    cap = iobackend.make_capture("Ethernet", "ip", lambda fr: None)   # ctor does not open
    assert type(cap) is NpcapCapture


def test_make_injector_is_native(monkeypatch):
    from backend.engine import npcap
    monkeypatch.setattr(npcap._wpcap, "resolve_npf_name", lambda n: "dev")
    monkeypatch.setattr(npcap._wpcap, "open_live", lambda *a, **k: 0x1)
    monkeypatch.setattr(npcap._wpcap, "close", lambda h: None)
    inj = iobackend.make_injector("Ethernet")
    assert type(inj).__name__ == "NpcapInjector"
    inj.close()


def test_no_env_var_can_select_the_scapy_oracle(monkeypatch):
    # Gate 6.4 removed the SHARKNET_BACKEND override; setting it must have NO effect.
    monkeypatch.setenv("SHARKNET_BACKEND", "scapy")
    assert iobackend.active_backend() == "native"
    cap = iobackend.make_capture("Ethernet", "ip", lambda fr: None)
    assert type(cap).__name__ == "NpcapCapture"


def test_no_production_module_imports_the_scapy_oracle():
    """No production module may IMPORT ScapyCapture/ScapyInjector (the oracle
    lives only in capture.py/injector.py, used by tests)."""
    offenders = []
    for root, _dirs, files in os.walk(ENGINE):
        if "__pycache__" in root:
            continue
        for fn in files:
            if not fn.endswith(".py") or fn in ("capture.py", "injector.py"):
                continue
            with open(os.path.join(root, fn), encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    s = line.strip()
                    if (s.startswith("from ") or s.startswith("import ")) and \
                       ("ScapyCapture" in s or "ScapyInjector" in s):
                        offenders.append(f"{fn}: {s}")
    assert not offenders, f"production modules import the scapy oracle: {offenders}"


def test_scapy_oracle_still_present_for_tests():
    # the oracle must remain importable for the equivalence tests
    from backend.engine.capture import ScapyCapture, Capture      # noqa: F401
    from backend.engine.injector import ScapyInjector, Injector   # noqa: F401
    assert ScapyCapture is not None and ScapyInjector is not None
