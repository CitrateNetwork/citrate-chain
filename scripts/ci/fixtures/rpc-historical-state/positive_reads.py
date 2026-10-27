"""Fixture (rpc-historical-state, positive): state reads pinned to a past block. The node
answers each with its latest state, so the comparison below is against the wrong snapshot.
Every marked line must be flagged."""


def code_at(rpc, addr, height):
    return rpc("eth_getCode", [addr, hex(height)])  # FLAG


def owner_at(rpc, to, data, block_hash):
    return rpc(
        "eth_call",  # FLAG
        [{"to": to, "data": data}, {"blockHash": block_hash}],
    )
