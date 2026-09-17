"""
V3.1 NotificationManager tests — the notification layer is EVENT/STATE -> TOAST,
never touching policy/enforcement. All logic here is headless-testable: feed()
returns the notifications it decided to emit, so assertions are deterministic
(no thread timing). The OS dispatch is an injected fake.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engine.notifications import (   # noqa: E402
    NotificationManager, Notification, DEFAULT_POLICY, CATEGORIES)


def _dev(ip, mode="allow", online=True, label=None, **kw):
    d = {"ip": ip, "mode": mode, "online": online, "is_self": False, "is_gateway": False}
    d["label"] = label or ip
    d.update(kw)
    return d


def _cats(emitted):
    return [n.category for n in emitted]


# ---------------- policy / init ----------------
def test_default_policy_matches_spec():
    m = NotificationManager()
    p = m.get_policy()
    assert p["enabled"] and p["new_device"] and p["device_offline"] and p["cut"] \
        and p["hardcut"] and p["security"]
    assert not p["device_online"] and not p["limit"] and not p["domain_block"] \
        and not p["service_block"] and not p["monitor_started"] and not p["speedtest"]


def test_set_policy_partial_merge_and_coercion():
    m = NotificationManager()
    m.set_policy({"limit": 1, "cut": 0, "bogus": True})   # coerced to bool; unknown ignored
    assert m.get_policy()["limit"] is True
    assert m.get_policy()["cut"] is False
    assert "bogus" not in m.get_policy()


def test_should_notify_respects_master_switch():
    m = NotificationManager(policy={"enabled": False})
    assert m.should_notify("cut") is False
    m.set_policy({"enabled": True})
    assert m.should_notify("cut") is True
    assert m.should_notify("limit") is False    # off by default


# ---------------- events -> notifications ----------------
def test_new_device_event_notifies():
    m = NotificationManager()
    out = m.feed([_dev("10.0.0.5", label="Ahmed-iPhone")],
                 [{"kind": "new_device", "ip": "10.0.0.5", "vendor": "Apple"}])
    assert _cats(out) == ["new_device"]
    assert "10.0.0.5" in out[0].body


def test_security_event_notifies_with_message():
    m = NotificationManager()
    out = m.feed([], [{"kind": "attack", "message": "ARP spoofing detected"}])
    assert _cats(out) == ["security"]
    assert out[0].body == "ARP spoofing detected"


def test_disabled_master_emits_nothing():
    m = NotificationManager(policy={"enabled": False})
    out = m.feed([_dev("10.0.0.5", mode="cut")],
                 [{"kind": "new_device", "ip": "10.0.0.5"}])
    assert out == []


# ---------------- derived transitions (no second monitor) ----------------
def test_cut_transition_notifies():
    m = NotificationManager()
    m.feed([_dev("10.0.0.5", mode="allow", label="PC")], [])          # establish prev
    out = m.feed([_dev("10.0.0.5", mode="cut", label="PC")], [])
    assert _cats(out) == ["cut"]
    assert "PC" in out[0].body and "cut from the network" in out[0].body


def test_hardcut_transition_notifies_distinctly():
    m = NotificationManager()
    m.feed([_dev("10.0.0.5", mode="allow", label="PC")], [])
    out = m.feed([_dev("10.0.0.5", mode="hardcut", label="PC")], [])
    assert _cats(out) == ["hardcut"]
    assert "completely cut" in out[0].body           # distinct from CUT wording
    # must NOT imply traffic was observed
    assert "observ" not in out[0].body.lower() and "monitor" not in out[0].body.lower()


def test_limit_transition_off_by_default():
    m = NotificationManager()
    m.feed([_dev("10.0.0.5", mode="allow")], [])
    out = m.feed([_dev("10.0.0.5", mode="limit")], [])
    assert out == []                                  # LIMIT default OFF
    m.set_policy({"limit": True})
    m.feed([_dev("10.0.0.5", mode="allow")], [])      # reset prev
    out = m.feed([_dev("10.0.0.5", mode="limit")], [])
    assert _cats(out) == ["limit"]


def test_offline_transition_notifies_online_does_not():
    m = NotificationManager()
    m.feed([_dev("10.0.0.5", online=True)], [])
    out = m.feed([_dev("10.0.0.5", online=False)], [])
    assert _cats(out) == ["device_offline"]
    out2 = m.feed([_dev("10.0.0.5", online=True)], [])   # back online — default OFF
    assert out2 == []


def test_no_repeat_when_state_unchanged():
    m = NotificationManager()
    m.feed([_dev("10.0.0.5", mode="cut")], [])
    out = m.feed([_dev("10.0.0.5", mode="cut")], [])     # same mode next tick
    assert out == []                                     # transition-based dedup


def test_self_and_gateway_never_notified():
    m = NotificationManager()
    m.feed([_dev("10.0.0.1", mode="allow", is_gateway=True),
            _dev("10.0.0.2", mode="allow", is_self=True)], [])
    out = m.feed([_dev("10.0.0.1", mode="cut", is_gateway=True),
                  _dev("10.0.0.2", mode="cut", is_self=True)], [])
    assert out == []


def test_new_device_same_tick_does_not_double_fire_mode():
    # a brand-new device that appears already cut fires new_device (from event),
    # NOT also a cut transition in the same tick (fresh_ips guard).
    m = NotificationManager()
    out = m.feed([_dev("10.0.0.9", mode="cut", label="X")],
                 [{"kind": "new_device", "ip": "10.0.0.9"}])
    assert _cats(out) == ["new_device"]


def test_no_fabricated_fields():
    # device with only an IP (no name/hostname) -> body is just the IP, no fake name
    m = NotificationManager()
    out = m.feed([_dev("10.0.0.5", label="10.0.0.5")],
                 [{"kind": "new_device", "ip": "10.0.0.5"}])
    assert out[0].body == "10.0.0.5"


# ---------------- async dispatch / robustness ----------------
def test_dispatch_failure_does_not_crash():
    def boom(title, body):
        raise RuntimeError("toast subsystem down")
    m = NotificationManager(dispatch=boom)
    m.start()
    m.feed([_dev("10.0.0.5", mode="allow")], [])
    m.feed([_dev("10.0.0.5", mode="cut")], [])       # enqueues -> worker calls boom
    time.sleep(0.2)
    # the manager is still alive and usable
    assert m.should_notify("cut") is True
    m.stop()


def test_worker_dispatches_to_os_callback():
    got = []
    m = NotificationManager(dispatch=lambda t, b: got.append((t, b)))
    m.start()
    m.feed([_dev("10.0.0.5", mode="allow", label="PC")], [])
    m.feed([_dev("10.0.0.5", mode="cut", label="PC")], [])
    for _ in range(50):
        if got:
            break
        time.sleep(0.02)
    assert got and got[0][0] == "Device blocked"
    m.stop()


def test_queue_bounded_under_storm_no_crash():
    m = NotificationManager(dispatch=None)   # no worker draining -> queue fills
    # emit far more than the queue cap in one shot; must not raise or grow unbounded
    devs_prev = [_dev(f"10.0.0.{i}", mode="allow") for i in range(200)]
    devs_cut = [_dev(f"10.0.0.{i}", mode="cut") for i in range(200)]
    m.feed(devs_prev, [])
    out = m.feed(devs_cut, [])
    assert len(out) == 200                    # feed() reports all decisions
    assert m._q.qsize() <= 64                 # but the queue never exceeds its cap


def test_stop_is_idempotent():
    m = NotificationManager(dispatch=lambda t, b: None)
    m.start()
    m.stop()
    m.stop()          # second stop must be safe
    assert True


def test_translate_injection_localizes():
    def tr(key, **kw):
        table = {"notif.cut.title": "قطع الجهاز", "notif.cut.body": "تم قطع {name}"}
        s = table.get(key)
        return s.format(**kw) if (s and kw) else s
    m = NotificationManager(translate=tr)
    m.feed([_dev("10.0.0.5", mode="allow", label="جهاز")], [])
    out = m.feed([_dev("10.0.0.5", mode="cut", label="جهاز")], [])
    assert out[0].title == "قطع الجهاز"
    assert "جهاز" in out[0].body


def test_all_categories_have_a_policy_key():
    p = DEFAULT_POLICY
    for c in CATEGORIES:
        assert c in p, f"category {c} missing a default-policy entry"
