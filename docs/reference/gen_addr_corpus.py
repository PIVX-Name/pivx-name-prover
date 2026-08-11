#!/usr/bin/env python3
"""Generates an address-validation corpus with verdicts derived from first principles.

This is the independent third implementation, in the same role the compact-SMT reference
plays: Rust (pins-core, which the circuit uses) and PHP (the indexer) are both checked
against it, so a divergence between host and guest shows up as a test failure instead of a
batch that the indexer queues and the prover cannot prove.
"""
import json
import random
import sys

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
PAYLOAD_LEN = 43  # 11-byte diversifier + 32-byte pk_d


def polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def convertbits(data, frm, to, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << to) - 1
    for v in data:
        if v < 0 or (v >> frm):
            return None
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv):
        return None
    return ret


def encode(hrp, payload):
    data = convertbits(payload, 8, 5, True)
    chk = polymod(hrp_expand(hrp) + data + [0] * 6) ^ 1
    checksum = [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def verdict(addr, net):
    """The policy, stated once: lowercase, exact hrp, exact length, 43-byte payload."""
    hrp, length = ("ps", 78) if net == "mainnet" else ("pts", 79)
    if addr == "" or addr.lower() != addr:
        return False
    if len(addr) != length:
        return False
    pos = addr.rfind("1")
    if pos < 1:
        return False
    if addr[:pos] != hrp:
        return False
    try:
        data = [CHARSET.index(c) for c in addr[pos + 1:]]
    except ValueError:
        return False
    if len(data) < 6:
        return False
    if polymod(hrp_expand(hrp) + data) != 1:
        return False
    payload = convertbits(data[:-6], 5, 8, pad=False)
    return payload is not None and len(payload) == PAYLOAD_LEN


def main():
    rng = random.Random(20260730)
    cases = []

    def add(addr, why):
        cases.append({"addr": addr, "why": why,
                      "mainnet": verdict(addr, "mainnet"),
                      "testnet": verdict(addr, "testnet")})

    # Valid addresses on each network.
    for hrp in ("ps", "pts"):
        for i in range(12):
            payload = bytes(rng.randrange(256) for _ in range(PAYLOAD_LEN))
            add(encode(hrp, payload), f"valid {hrp}")

    # Wrong payload sizes under a correct prefix: the case a length-only check misses.
    for hrp in ("ps", "pts"):
        for n in (32, 42, 44, 64):
            payload = bytes(rng.randrange(256) for _ in range(n))
            add(encode(hrp, payload), f"{hrp} payload {n}B")

    # Legacy testnet form, and other PIVX-ish prefixes.
    for hrp in ("ptestsapling", "p", "pss", "pt", "ptest"):
        add(encode(hrp, bytes(rng.randrange(256) for _ in range(PAYLOAD_LEN))), f"hrp {hrp}")

    # Mutations of a valid address: checksum breakage, case, truncation, padding.
    base = {h: encode(h, bytes(rng.randrange(256) for _ in range(PAYLOAD_LEN)))
            for h in ("ps", "pts")}
    for hrp, addr in base.items():
        add(addr.upper(), f"{hrp} uppercase")
        add(addr.capitalize(), f"{hrp} mixed case")
        add(addr[:-1], f"{hrp} truncated")
        add(addr + CHARSET[0], f"{hrp} extended")
        for pos in (len(hrp) + 1, len(addr) // 2, len(addr) - 1):
            c = addr[pos]
            repl = CHARSET[(CHARSET.index(c) + 1) % len(CHARSET)] if c in CHARSET else "q"
            add(addr[:pos] + repl + addr[pos + 1:], f"{hrp} flip at {pos}")
        add(addr.replace("1", "", 1), f"{hrp} no separator")

    # Non-bech32 and foreign-coin inputs.
    for a in ("", "not-an-address", "1", "ps", "pts", "ps1",
              "DAbxRxCXA6vghAMFHmXfmvsLNqCvGjqTvA",
              "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly",
              "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"):
        add(a, "foreign/malformed")

    json.dump(cases, sys.stdout, indent=1)
    print(file=sys.stderr)
    print(f"  {len(cases)} cases; "
          f"mainnet-valid={sum(c['mainnet'] for c in cases)} "
          f"testnet-valid={sum(c['testnet'] for c in cases)}", file=sys.stderr)


if __name__ == "__main__":
    main()
