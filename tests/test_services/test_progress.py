import pytest
from app.services import progress


@pytest.mark.asyncio
async def test_publish_delivers_to_subscriber():
    q = progress.subscribe("inv-1")
    try:
        progress.publish("inv-1", {"event": "agent_completed", "agent": "recon"})
        event = q.get_nowait()
        assert event["agent"] == "recon"
    finally:
        progress.unsubscribe("inv-1", q)


@pytest.mark.asyncio
async def test_publish_reaches_all_subscribers():
    q1 = progress.subscribe("inv-2")
    q2 = progress.subscribe("inv-2")
    try:
        progress.publish("inv-2", {"event": "x"})
        assert q1.get_nowait() == {"event": "x"}
        assert q2.get_nowait() == {"event": "x"}
    finally:
        progress.unsubscribe("inv-2", q1)
        progress.unsubscribe("inv-2", q2)


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery():
    q = progress.subscribe("inv-3")
    progress.unsubscribe("inv-3", q)
    progress.publish("inv-3", {"event": "x"})
    assert q.empty()


def test_publish_without_subscribers_is_noop():
    progress.publish("inv-never-subscribed", {"event": "x"})


@pytest.mark.asyncio
async def test_isolation_between_investigations():
    qa = progress.subscribe("inv-a")
    qb = progress.subscribe("inv-b")
    try:
        progress.publish("inv-a", {"event": "only-a"})
        assert qa.get_nowait() == {"event": "only-a"}
        assert qb.empty()
    finally:
        progress.unsubscribe("inv-a", qa)
        progress.unsubscribe("inv-b", qb)
