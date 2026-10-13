from triage.mq import Topology


def test_retry_tiers_grow_then_cap():
    topo = Topology(None, None, None, None, None, retry_delays=(2, 8, 32, 128))  # type: ignore[arg-type]
    keys = [topo.retry_routing_key(n) for n in range(1, 7)]
    assert keys == [
        "triage.retry.2s",
        "triage.retry.8s",
        "triage.retry.32s",
        "triage.retry.128s",
        "triage.retry.128s",
        "triage.retry.128s",
    ]
