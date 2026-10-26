"""broadcast_ident.py: the identity keep_check.sh gives a deployment in a Foundry broadcast.

A deployment forge recorded with its contract name is identified by that name. Forge records
no name for a contract it has no artifact for, such as the P-256 verifier, which
aa/DeployP256Verifier.s.sol deploys from vendored init code through the CREATE2 factory
(transactionType CREATE2, contractName null, transaction.to = the factory, input = salt ||
init code). Such a deployment is identified by its init code instead:
"initcode:<keccak256(init code)>", but only when the record proves its own address, i.e.
contractAddress == CREATE2(transaction.to, salt, keccak256(init code)). A nameless record that
does not prove its address has no identity, and the gate refuses it.

keccak256 is the original Keccak (Ethereum), not FIPS SHA3-256, so it is implemented here;
the standard library has only the latter.
"""
import re

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M = (1 << 64) - 1


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                v = a[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & _M if r else v
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off : off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        a = _f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")


def create2_address(factory: str, salt: bytes, init_code: bytes) -> str:
    h = keccak256(b"\xff" + bytes.fromhex(factory[2:]) + salt + keccak256(init_code))
    return "0x" + h[12:].hex()


def identity(t):
    """(identity, None) for a CREATE/CREATE2 record t, or (None, reason)."""
    name = t.get("contractName")
    if isinstance(name, str) and name:
        return name, None
    a = t.get("contractAddress")
    if not isinstance(a, str) or not _ADDR.fullmatch(a):
        return None, "a nameless deployment without a contract address"
    tx = t.get("transaction") if isinstance(t.get("transaction"), dict) else {}
    to, data = tx.get("to"), tx.get("input", tx.get("data"))
    if t.get("transactionType") != "CREATE2" or not isinstance(to, str) or not _ADDR.fullmatch(to):
        return None, f"a nameless deployment at {a.lower()} that is not a CREATE2 factory call, so its record cannot prove its address"
    if not isinstance(data, str) or not _HEX.fullmatch(data) or len(data) < 2 + 2 * 33:
        return None, f"a nameless CREATE2 at {a.lower()} whose input is not salt || init code"
    raw = bytes.fromhex(data[2:])
    salt, init = raw[:32], raw[32:]
    if create2_address(to.lower(), salt, init) != a.lower():
        return None, f"a nameless CREATE2 at {a.lower()} whose record does not prove that address (CREATE2 of its factory, salt and init code is elsewhere)"
    return "initcode:0x" + keccak256(init).hex(), None
