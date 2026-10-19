"""Fixture (rpc-historical-state, negative): latest/pending reads, and a stub server's method
dispatch. Nothing here may be flagged."""


def code(rpc, addr):
    return rpc("eth_getCode", [addr, "latest"])


def nonce(rpc, addr):
    return rpc(
        "eth_getTransactionCount",
        [addr, "pending"],
    )


def handle(m, params):
    if m == "eth_call":
        return "0x01"
    return {"eth_getCode": lambda p: "0x"}[m](params)


def balance(rpc, addr):
    params = [addr, "latest"]
    return rpc("eth_getBalance", params)


MATCH_NONCE = {"method": "eth_getTransactionCount"}
