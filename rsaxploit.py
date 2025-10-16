#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
RsaXploit — one-file, professional RSA CTF exploitation suite (Lite / CTF Edition).

Usage examples:
  python3 rsaxploit.py --publickey pub.pem --decrypt "123456"
  python3 rsaxploit.py -n "0xDEAD...,0xBEEF..." -e "3" --decrypt "C1,C2"
  python3 rsaxploit.py -n N -e 65537 --decrypt C --flag-format 'CTF\{.*?\}'
  python3 rsaxploit.py cipher.txt   # parse keys/ciphers from file (many supported formats)
"""

import argparse
import base64
import binascii
import logging
import math
import os
import re
import sys
import textwrap
import time
import threading
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict

# Third-party
try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import long_to_bytes, bytes_to_long
except Exception:
    print("Please install pycryptodome: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)

try:
    import gmpy2
except Exception:
    gmpy2 = None

# FactorDB (optional)
try:
    from factordb.factordb import FactorDB
except Exception:
    FactorDB = None


# ========= Colors & UI =========
class Colors:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"

    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    CYANBLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"
    BLUE = "\x1b[34m"

def banner() -> str:
    # multi-color banner (static)
    return (
        f"{Colors.CYAN}╔════════════════════════════════════════════════════════════════╗\n"
        f"{Colors.CYAN}║                  {Colors.BOLD}    R S A X p l O i T          {Colors.RESET}{Colors.CYAN}               ║\n"
        f"{Colors.CYAN}║            {Colors.RESET} {Colors.YELLOW}Automated RSA Attack & CTF Framework              {Colors.RESET}{Colors.CYAN} ║\n"
        f"{Colors.CYAN}║           {Colors.RED} {Colors.BOLD}Author: Shoaib Bin Rashid (R3D_XplOiT) {Colors.RESET}{Colors.CYAN}             ║\n"
        f"{Colors.CYAN}╚════════════════════════════════════════════════════════════════╝{Colors.RESET}\n"
    )

def box(title: str, lines: List[str]) -> str:
    if not lines:
        lines = [""]
    w = max(len(title) + 2, *(len(l) for l in lines)) + 4
    top = "╔" + "═" * (w - 2) + "╗"
    mid = "╠" + "═" * (w - 2) + "╣"
    bot = "╚" + "═" * (w - 2) + "╝"
    out = [top, f"║ {title.center(w-4)} ║", mid]
    for l in lines:
        out.append("║ " + l.ljust(w - 4) + " ║")
    out.append(bot)
    return "\n".join(out)

def one_line(status_ok: Optional[bool], name: str, dt: float) -> str:
    # status_ok: True/False/None (None = SKIP)
    if status_ok is True:
        status = f"{Colors.GREEN}✓ OK{Colors.RESET}"
    elif status_ok is False:
        status = f"{Colors.RED}✗ FAIL{Colors.RESET}"
    else:
        status = f"{Colors.YELLOW}↷ SKIP{Colors.RESET}"
    return f"{Colors.CYAN}→ {Colors.BOLD}{name:<28}{Colors.RESET} {status} {Colors.DIM}[{dt:.2f}s]{Colors.RESET}"


# ========= Utils =========
def parse_int_auto(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    # allow underscores like Python literal 1_000
    return int(s.replace("_", ""))

def parse_cipher_auto(s: str) -> int:
    """Ultra-flexible number parsing. Handles almost any format."""
    s = s.strip()
    
    # Remove common prefixes and suffixes
    s = re.sub(r'^["\'«»\[\{\(]', '', s)  # Remove quotes, brackets
    s = re.sub(r'["\'«»\]\}\),;]*$', '', s)  # Remove trailing chars
    s = s.strip()
    
    if not s:
        raise ValueError("Empty value")
    
    # Method 1: Standard decimal/hex parsing
    try:
        return parse_int_auto(s)
    except Exception:
        pass
    
    # Method 2: Pure hex without 0x prefix
    if re.match(r'^[0-9A-Fa-f]+$', s) and len(s) > 3:
        try:
            return int(s, 16)
        except Exception:
            pass
    
    # Method 3: Base64 (strict)
    if re.match(r'^[A-Za-z0-9+/]+=*$', s) and len(s) % 4 == 0:
        try:
            return bytes_to_long(base64.b64decode(s, validate=True))
        except Exception:
            pass
    
    # Method 4: Base64 (loose - common in CTFs)
    if re.match(r'^[A-Za-z0-9+/_-]+$', s) and len(s) > 4:
        try:
            # Try with URL-safe base64
            decoded = base64.urlsafe_b64decode(s + '==')  # Add padding
            return bytes_to_long(decoded)
        except Exception:
            pass
    
    # Method 5: Raw hex bytes (no spaces)
    if re.match(r'^[0-9A-Fa-f]+$', s) and len(s) % 2 == 0:
        try:
            return bytes_to_long(binascii.unhexlify(s))
        except Exception:
            pass
    
    # Method 6: Hex with spaces or separators
    if re.search(r'[0-9A-Fa-f][\s:_-]+[0-9A-Fa-f]', s):
        try:
            cleaned = re.sub(r'[\s:_-]+', '', s)
            if re.match(r'^[0-9A-Fa-f]+$', cleaned):
                return bytes_to_long(binascii.unhexlify(cleaned))
        except Exception:
            pass
    
    # Method 7: Octal (0o prefix)
    if s.startswith('0o') or s.startswith('0O'):
        try:
            return int(s, 8)
        except Exception:
            pass
    
    # Method 8: Binary (0b prefix)
    if s.startswith('0b') or s.startswith('0B'):
        try:
            return int(s, 2)
        except Exception:
            pass
    
    # Method 9: Scientific notation
    if 'e' in s.lower() or 'E' in s:
        try:
            return int(float(s))
        except Exception:
            pass
    
    # Method 10: Try as ASCII string (last resort)
    if len(s) <= 64 and all(32 <= ord(c) < 127 for c in s):
        try:
            return bytes_to_long(s.encode('ascii'))
        except Exception:
            pass
    
    # Method 11: Extract first long number found
    numbers = re.findall(r'\d{8,}', s)
    if numbers:
        try:
            return int(numbers[0])
        except Exception:
            pass
    
    # Method 12: Extract hex sequences
    hex_matches = re.findall(r'[0-9A-Fa-f]{8,}', s)
    if hex_matches:
        try:
            return int(hex_matches[0], 16)
        except Exception:
            pass
    
    raise ValueError(f"Cannot parse value in any known format: {s!r}")

def split_arg_tokens(arg_values: Optional[List[str]]) -> List[str]:
    """
    Accepts argparse token list (nargs='+') and splits comma-separated items,
    e.g. ["123,456", "789"] -> ["123","456","789"]
    If arg_values is None -> []
    """
    if not arg_values:
        return []
    out = []
    for tok in arg_values:
        tok = tok.strip()
        if not tok:
            continue
        # split by commas but preserve items with spaces if quoted by shell
        parts = [p.strip() for p in tok.split(",") if p.strip()]
        out.extend(parts)
    return out

def parse_ciphers_from_arg(values: Optional[List[str]]) -> List[int]:
    toks = split_arg_tokens(values)
    out = []
    for t in toks:
        out.append(parse_cipher_auto(t))
    return out

def is_printable_bytes(b: bytes) -> bool:
    try:
        s = b.decode('ascii')
    except Exception:
        return False
    # consider printable if at least 90% printable chars
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127)
    return printable >= 0.9 * max(1, len(s))


# ========= Data =========
@dataclass
class PubKey:
    n: int
    e: int
    label: str = ""
    extras: Dict[str, str] = None  # arbitrary extra values parsed from input (e.g. 'x')

@dataclass
class AttackResult:
    name: str
    success: bool
    plaintext: Optional[bytes] = None
    info: str = ""
    recovered_d: Optional[int] = None
    recovered_pq: Optional[Tuple[int, int]] = None


# ========= Attack Base =========
class Attack:
    name = "base"
    priority = 999
    def can_run(self, keys: List[PubKey], c_list: List[int], args) -> bool:
        return True
    def run(self, keys: List[PubKey], c_list: List[int], args, log) -> AttackResult:
        return AttackResult(self.name, False, None, info="not implemented")


# ========= Cheap Attacks =========
class SmallRootAttack(Attack):
    name = "small_root"; priority = 5
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1 and len(c_list) >= 1 and (keys[0].e <= 11)
    def run(self, keys, c_list, args, log):
        e = keys[0].e
        for c in c_list:
            try:
                if gmpy2:
                    m, ok = gmpy2.iroot(c, e)
                    if ok:
                        return AttackResult(self.name, True, long_to_bytes(int(m)), info="m^e < n")
                else:
                    m = int(round(c ** (1.0 / e)))
                    if pow(m, e) == c:
                        return AttackResult(self.name, True, long_to_bytes(m), info="m^e < n")
            except Exception:
                pass
        return AttackResult(self.name, False, info="small_root")

class HastadsBroadcastAttack(Attack):
    name = "hastads_broadcast"; priority = 85
    def can_run(self, keys, c_list, args):
        if len(keys) < 2 or len(c_list) < 2:
            return False
        es = {}
        for k in keys:
            es.setdefault(k.e, []).append(k.n)
        for e, ns in es.items():
            if len(ns) >= e:
                return True
        return False
    def run(self, keys, c_list, args, log):
        L = min(len(keys), len(c_list))
        if L < 2:
            return AttackResult(self.name, False, info="need pairs")
        groups: Dict[int, Tuple[List[int], List[int]]] = {}
        for i in range(L):
            e = keys[i].e
            groups.setdefault(e, ([], []))
            groups[e][0].append(keys[i].n)
            groups[e][1].append(c_list[i])
        for e, (n_list, cvals) in groups.items():
            if len(n_list) < e or len(cvals) < e:
                continue
            try:
                M_e = crt(cvals, n_list)
            except Exception:
                return AttackResult(self.name, False, info="CRT")
            if gmpy2:
                m, ok = gmpy2.iroot(M_e, e)
                if ok:
                    return AttackResult(self.name, True, long_to_bytes(int(m)), info=f"e={e}")
            else:
                m = int(round(M_e ** (1.0 / e)))
                if pow(m, e) == M_e:
                    return AttackResult(self.name, True, long_to_bytes(m), info=f"e={e}")
        return AttackResult(self.name, False, info="hastads")


class SharedPrimeGCDAttack(Attack):
    name = "sharedprime_gcd"
    priority = 9

    def can_run(self, keys, c_list, args):
        return len(keys) >= 2

    def run(self, keys, c_list, args, log):
        n = len(keys)
        gcd_map = {}  # (i,j) -> gcd
        factors = [set() for _ in range(n)]

        # Step 1: Compute all pairwise gcds
        for i in range(n):
            for j in range(i + 1, n):
                ni, nj = keys[i].n, keys[j].n
                g = math.gcd(ni, nj)
                if 1 < g < ni and 1 < g < nj:
                    gcd_map[(i, j)] = g
                    factors[i].add(g)
                    factors[j].add(g)

        if not gcd_map:
            return AttackResult(self.name, False, info="no-shared-prime")

        # Step 2: Compute missing co-factors
        for i in range(n):
            for g in list(factors[i]):
                other = keys[i].n // g
                if other != g:
                    factors[i].add(other)

        # Step 3: Build φ(n) for each key if possible
        recovered = []
        for i in range(n):
            if len(factors[i]) == 2:
                p, q = sorted(factors[i])
                phi = (p - 1) * (q - 1)
                try:
                    d = invmod(keys[i].e, phi)
                except Exception:
                    continue
                recovered.append((i, p, q, d))

        # Step 4: Try decrypting any ciphertext
        for idx, p, q, d in recovered:
            if idx < len(c_list):
                c = c_list[idx]
            elif c_list:
                c = c_list[0]
            else:
                continue
            try:
                m = pow(c, d, keys[idx].n)
                pt = long_to_bytes(m)
                return AttackResult(
                    self.name, True, pt,
                    info=f"shared primes ({idx})",
                    recovered_d=d,
                    recovered_pq=(p, q)
                )
            except Exception as ex:
                log.debug(f"[sharedprime_gcd] decrypt fail {ex}")
                continue

        # If we reach here, found factors but couldn’t decrypt
        return AttackResult(self.name, False, info="found-shared-but-no-decrypt")

class SharedPrimePolynomialAttack(Attack):
    name = "sharedprime_polynomial"
    priority = 8

    def can_run(self, keys, c_list, args):
        # Need one ciphertext and at least 2 moduli to make sense
        return len(keys) >= 2 and len(c_list) >= 1

    def run(self, keys, c_list, args, log):
        # 1) Factor via gcds
        n_count = len(keys)
        factors: Dict[int, Tuple[int,int]] = {}  # idx -> (p,q)
        ns = [k.n for k in keys]

        for i in range(n_count):
            if i in factors:
                continue
            for j in range(i+1, n_count):
                g = math.gcd(ns[i], ns[j])
                if 1 < g < ns[i] and 1 < g < ns[j]:
                    p = g
                    qi = ns[i] // p
                    qj = ns[j] // p
                    if p * qi == ns[i]:
                        factors[i] = (p, qi)
                    if p * qj == ns[j]:
                        factors[j] = (p, qj)

        if not factors:
            return AttackResult(self.name, False, info="no-gcd-factors")

        # 2) compute d_i for each factored modulus
        d_map: Dict[int, int] = {}
        for i, (p, q) in factors.items():
            try:
                phi = (p - 1) * (q - 1)
                d_map[i] = invmod(keys[i].e, phi)
            except Exception as ex:
                log.debug(f"[chained_sharedprime] invmod failed for n#{i}: {ex}")

        if not d_map:
            return AttackResult(self.name, False, info="no-d")

        # 3) try chained decryptions over permutations (cap to 4 layers)
        from itertools import permutations

        layer_indices = list(d_map.keys())
        max_layers = min(4, len(layer_indices))  # safety cap

        c0 = c_list[0]
        best_candidate = None
        readable_hits = []

        def _is_readable(b: bytes) -> bool:
            try:
                s = b.decode("utf-8")
            except Exception:
                return False
            # printable-ish heuristic
            ok = sum(1 for ch in s if (32 <= ord(ch) < 127) or ch in "\n\r\t{}_-")
            return ok >= 0.85 * max(1, len(s))

        flag_re = None
        if getattr(args, "flag_format", None):
            try:
                flag_re = re.compile(args.flag_format)
            except Exception:
                flag_re = None

        for L in range(1, max_layers + 1):
            for order in permutations(layer_indices, L):
                try:
                    m = c0
                    for idx in order:
                        m = pow(m, d_map[idx], ns[idx])
                    pt = long_to_bytes(m)
                except Exception as ex:
                    log.debug(f"[chained_sharedprime] decrypt order {order} failed: {ex}")
                    continue

                text = None
                try:
                    text = pt.decode("utf-8")
                except Exception:
                    pass

                # Prefer explicit flag regex if supplied
                if flag_re and text and flag_re.search(text):
                    return AttackResult(
                        self.name, True, pt,
                        info=f"layers={L}, order={order}",
                        recovered_d=None, recovered_pq=None
                    )

                # Otherwise collect readable candidates
                if pt and _is_readable(pt):
                    readable_hits.append((order, pt))
                    if best_candidate is None:
                        best_candidate = (order, pt)

        if readable_hits:
            # Print all readable hits (UTF-8 only)
            print(f"\n{Colors.GREEN}{Colors.BOLD}✔ Chained RSA: readable candidates{Colors.RESET}\n")
            for order, pt in readable_hits:
                try:
                    s = pt.decode("utf-8").strip()
                except Exception:
                    continue
                print(f"{Colors.CYAN}→ order {order}{Colors.RESET}")
                print(f"{Colors.BOLD}UTF-8:{Colors.RESET} {s}\n")

            order, pt = readable_hits[0]
            return AttackResult(self.name, True, pt, info=f"layers≈{len(order)}, order={order}")

        # If nothing readable, still return first candidate (if any)
        if best_candidate:
            order, pt = best_candidate
            return AttackResult(self.name, True, pt, info=f"layers≈{len(order)}, order={order}")

        return AttackResult(self.name, False, info="no-readable-candidate")



class CommonModulusBezoutAttack(Attack):
    name = "common_modulus_bezout"; priority = 10
    def can_run(self, keys, c_list, args):
        if len(keys) < 2 or len(c_list) < 2:
            return False
        ns = [k.n for k in keys]
        return len(set(ns)) == 1 and len(set(k.e for k in keys)) >= 2
    def run(self, keys, c_list, args, log):
        n = keys[0].n
        e1, e2 = keys[0].e, keys[1].e
        c1, c2 = c_list[0], c_list[1]
        u, v = bezout(e1, e2)
        if e1*u + e2*v != 1:
            return AttackResult(self.name, False, info="bezout")
        try:
            # handle negative exponents
            if u < 0:
                c1 = invmod(c1, n)
                u = -u
            if v < 0:
                c2 = invmod(c2, n)
                v = -v
            a = pow(c1, u, n)
            b = pow(c2, v, n)
            m = (a*b) % n
            return AttackResult(self.name, True, long_to_bytes(m), info="same n, diff e")
        except Exception as ex:
            log.debug(f"[bezout] {ex}")
            return AttackResult(self.name, False, info="common-mod")


class WienerAttack(Attack):
    name = "wiener"; priority = 12
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1
    def run(self, keys, c_list, args, log):
        k = keys[0]
        d = wiener_attack(k.e, k.n)
        if d is None:
            return AttackResult(self.name, False, info="wiener")
        if c_list:
            m = pow(c_list[0], d, k.n)
            return AttackResult(self.name, True, long_to_bytes(m), info="small d", recovered_d=d)
        return AttackResult(self.name, True, None, info="small d", recovered_d=d)


# ========= Moderate / Expensive =========
class FermatAttack(Attack):
    name = "fermat"; priority = 95
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1
    def run(self, keys, c_list, args, log):
        k = keys[0]
        p, q = fermat_factor(k.n, max_steps=200000)
        if not p or not q:
            return AttackResult(self.name, False, info="fermat")
        phi = (p-1)*(q-1)
        d = invmod(k.e, phi)
        if c_list:
            m = pow(c_list[0], d, k.n)
            return AttackResult(self.name, True, long_to_bytes(m), info="close p,q", recovered_d=d, recovered_pq=(p,q))
        return AttackResult(self.name, True, None, info="close p,q", recovered_d=d, recovered_pq=(p,q))


class PollardRhoAttack(Attack):
    name = "pollard_rho"; priority = 90
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1
    def run(self, keys, c_list, args, log):
        k = keys[0]
        p = pollard_rho(k.n)
        if not p:
            return AttackResult(self.name, False, info="rho")
        q = k.n // p
        if p * q != k.n:
            return AttackResult(self.name, False, info="rho-bad")
        d = invmod(k.e, (p-1)*(q-1))
        if c_list:
            m = pow(c_list[0], d, k.n)
            return AttackResult(self.name, True, long_to_bytes(m), info="rho", recovered_d=d, recovered_pq=(p,q))
        return AttackResult(self.name, True, None, info="rho", recovered_d=d, recovered_pq=(p,q))


class PollardP1Attack(Attack):
    name = "pollard_p1"; priority = 70
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1
    def run(self, keys, c_list, args, log):
        k = keys[0]
        p = pollard_p1(k.n, B=20000)
        if not p:
            return AttackResult(self.name, False, info="p-1")
        q = k.n // p
        if p * q != k.n:
            return AttackResult(self.name, False, info="p-1-bad")
        d = invmod(k.e, (p-1)*(q-1))
        if c_list:
            m = pow(c_list[0], d, k.n)
            return AttackResult(self.name, True, long_to_bytes(m), info="p-1", recovered_d=d, recovered_pq=(p,q))
        return AttackResult(self.name, True, None, info="p-1", recovered_d=d, recovered_pq=(p,q))


class TrialDivisionAttack(Attack):
    name = "trial_division"; priority = 20
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1
    def run(self, keys, c_list, args, log):
        k = keys[0]
        p = trial_division(k.n, limit=300000)
        if not p:
            return AttackResult(self.name, False, info="trial")
        q = k.n // p
        d = invmod(k.e, (p-1)*(q-1))
        if c_list:
            m = pow(c_list[0], d, k.n)
            return AttackResult(self.name, True, long_to_bytes(m), info="small prime", recovered_d=d, recovered_pq=(p,q))
        return AttackResult(self.name, True, None, info="small prime", recovered_d=d, recovered_pq=(p,q))


class FactorDBAttack(Attack):
    name = "factordb"; priority = 25
    def can_run(self, keys, c_list, args):
        return FactorDB is not None and len(keys) >= 1
    def run(self, keys, c_list, args, log):
        k = keys[0]
        try:
            fdb = FactorDB(k.n); fdb.connect()
            factors = fdb.get_factor_list()
            if not factors or len(factors) != 2:
                return AttackResult(self.name, False, info="fdb-miss")
            p, q = int(factors[0]), int(factors[1])
            if p * q != k.n:
                return AttackResult(self.name, False, info="fdb-bad")
            d = invmod(k.e, (p-1)*(q-1))
            if c_list:
                m = pow(c_list[0], d, k.n)
                return AttackResult(self.name, True, long_to_bytes(m), info="FactorDB", recovered_d=d, recovered_pq=(p,q))
            return AttackResult(self.name, True, None, info="FactorDB", recovered_d=d, recovered_pq=(p,q))
        except Exception:
            return AttackResult(self.name, False, info="fdb-error")


class KnownSumAttack(Attack):
    """
    When an extra 'x' is known for the key and x relates to p/q via a quadratic,
    compute p,q using integer sqrt and recover d. Example uses the same
    algebra you showed in the snippet.
    NOTE: adjust algebra if your x formula differs (e.g., x = p+q, x = p-q, etc.)
    """
    name = "known_sum"
    priority = 6  # cheap, run early

    def can_run(self, keys, c_list, args,):
        # only if at least one key and first key has extras with x and at least one cipher
        return len(keys) >= 1 and keys[0].extras and 'x' in keys[0].extras and len(c_list) >= 1

    def run(self, keys, c_list, args, log):
        k = keys[0]
        try:
            x_raw = k.extras['x']
            x_val = parse_int_auto(x_raw)
        except Exception:
            # try hex fallback, or base64? keep robust attempts:
            try:
                x_val = int(x_raw, 16)
            except Exception as ex:
                log.debug(f"[known_sum] cannot parse x: {x_raw}: {ex}")
                return AttackResult(self.name, False, info="x-parse")

        # Solve quadratic depending on expected relation.
        # The snippet you showed solved for p,q using:
        #   p and q are roots of t^2 + x*t - n = 0  (verify algebra)
        # delta = x^2 - 4*n
        delta = x_val * x_val - 4 * k.n
        if delta < 0:
            return AttackResult(self.name, False, info="delta-neg")
        # integer sqrt
        if gmpy2:
            s = int(gmpy2.isqrt(delta))
        else:
            s = int(math.isqrt(delta))
        if s * s != delta:
            return AttackResult(self.name, False, info="delta-not-square")
        # compute roots — match your snippet's signs
        p = (x_val - s) // 2
        q = (x_val + s) // 2
        if p <= 1 or q <= 1 or p * q != k.n:
            # try swapped sign just in case
            p_alt = ( - x_val - s ) // -2
            q_alt = ( - x_val + s ) // -2
            if p_alt > 1 and q_alt > 1 and p_alt * q_alt == k.n:
                p, q = p_alt, q_alt
            else:
                return AttackResult(self.name, False, info="roots-bad")

        try:
            phi = (p - 1) * (q - 1)
            d = invmod(k.e, phi)
        except Exception as ex:
            log.debug(f"[known_sum] invmod error: {ex}")
            return AttackResult(self.name, False, info="invmod")

        # decrypt first provided ciphertext
        if c_list:
            m = pow(c_list[0], d, k.n)
            return AttackResult(self.name, True, long_to_bytes(m), info="known x", recovered_d=d, recovered_pq=(p, q))

        return AttackResult(self.name, True, None, info="known x", recovered_d=d, recovered_pq=(p, q))

class PolynomialGuessAttack(Attack):
    """
    When p and q are generated as known polynomials in a shared small / bounded x,
    search for x (binary search) and recover p,q,d,m.
    This implementation is specific to the polynomials from your example (degree 6).
    If you want to support other polynomials, make this configurable.
    """
    name = "polynomial_guess"
    priority = 50  # place among moderate attacks

    def can_run(self, keys, c_list, args):
        # only if we have at least 1 key and at least 1 ciphertext to decrypt
        return len(keys) >= 1 and len(c_list) >= 1

    def run(self, keys, c_list, args, log):
        # only operate on the first key/cipher for now (extendable)
        k = keys[0]
        n = k.n
        e = k.e
        c = c_list[0]

        # define the polynomials (replace these if you need other polynomials)
        def p_of(x):
            # p = 4*x**6 - 3*x**5 + 11*x**4 + 20*x**3 - 45*x**2 - 330*x - 17278375800565216289
            return (4 * x**6
                    - 3 * x**5
                    + 11 * x**4
                    + 20 * x**3
                    - 45 * x**2
                    - 330 * x
                    - 17278375800565216289)

        def q_of(x):
            # q = 5*x**6 + 27*x**5 - 2*x**4 + 9*x**3 - 192*x**2 + 78*x + 10651084407042190747
            return (5 * x**6
                    + 27 * x**5
                    - 2 * x**4
                    + 9 * x**3
                    - 192 * x**2
                    + 78 * x
                    + 10651084407042190747)

        # binary search bounds for 64-bit random integer x
        lo = 1 << 63
        hi = (1 << 64) - 1

        # quick sanity check: if p(lo)*q(lo) > n and p(hi)*q(hi) < n then binary search cannot find
        # we simply run binary search until lo>hi
        tries = 0
        while lo <= hi:
            tries += 1
            mid = (lo + hi) // 2
            # compute product (big integers; Python handles bigints fine)
            try:
                prod = p_of(mid) * q_of(mid)
            except Exception as ex:
                log.debug(f"[polynomial_guess] arithmetic error: {ex}")
                return AttackResult(self.name, False, info="arith-error")
            if prod == n:
                # found x; recover p,q,d and decrypt
                P = p_of(mid)
                Q = q_of(mid)
                if P * Q != n:
                    return AttackResult(self.name, False, info="prod-mismatch")
                try:
                    phi = (P - 1) * (Q - 1)
                    d = invmod(e, phi)
                except Exception as ex:
                    log.debug(f"[polynomial_guess] invmod error: {ex}")
                    return AttackResult(self.name, False, info="invmod")
                try:
                    m = pow(c, d, n)
                    pt = long_to_bytes(m)
                    return AttackResult(self.name, True, pt, info=f"x={mid}", recovered_d=d, recovered_pq=(P, Q))
                except Exception as ex:
                    log.debug(f"[polynomial_guess] decrypt error: {ex}")
                    return AttackResult(self.name, True, None, info=f"x={mid}")
            elif prod > n:
                hi = mid - 1
            else:
                lo = mid + 1

            # tiny guard to avoid locking forever (should not trigger on 64-bit)
            if tries > 500:
                # give up - too many iterations (shouldn't happen: binary search uses ~64 iterations)
                break

        return AttackResult(self.name, False, info="not-found")


class CoppersmithAttack(Attack):
    """
    Coppersmith's attack for finding small roots of polynomial equations mod N.
    Handles stereotyped messages, partial key recovery, and related message attacks.
    """
    name = "coppersmith"
    priority = 15  # Between wiener (12) and trial_division (20)
    
    def can_run(self, keys, c_list, args):
        return len(keys) >= 1 and len(c_list) >= 1 and keys[0].e <= 5
    
    def run(self, keys, c_list, args, log):
        k = keys[0]
        n, e = k.n, k.e
        c = c_list[0]
        
        # Common CTF patterns to try
        patterns = [
            b"The flag is ",
            b"FLAG{",
            b"CTF{",
            b"flag{",
            b"picoCTF{",
            b"DUCTF{",
            b"password is ",
            b"secret: ",
            b"key is ",
            b"answer: ",
            b"Solution: ",
            b"Flag: ",
        ]
        
        # Try different unknown lengths
        for unknown_len in [8, 12, 16, 20, 24, 32]:
            for pattern in patterns:
                log.debug(f"[coppersmith] trying pattern {pattern} with {unknown_len} unknown bytes")
                
                result = find_stereotyped_message(n, e, c, pattern, unknown_len)
                if result:
                    # Verify the result makes sense
                    if self._is_valid_plaintext(result):
                        return AttackResult(
                            self.name, True, result, 
                            info=f"stereotyped msg: {pattern.decode('ascii', errors='ignore')[:10]}..."
                        )
        
        # Try suffix patterns (known ending)
        suffix_patterns = [
            b"}",  # Common flag ending
            b".txt",
            b".flag",
        ]
        
        for suffix in suffix_patterns:
            for unknown_len in [8, 12, 16, 20]:
                result = self._try_suffix_pattern(n, e, c, suffix, unknown_len, log)
                if result and self._is_valid_plaintext(result):
                    return AttackResult(
                        self.name, True, result,
                        info=f"suffix pattern: ...{suffix.decode('ascii', errors='ignore')}"
                    )
        
        # Try common padding attacks
        if e == 3:
            result = self._try_padding_attack(n, e, c, log)
            if result:
                return AttackResult(self.name, True, result, info="padding attack")
        
        return AttackResult(self.name, False, info="no stereotyped patterns found")
    
    def _is_valid_plaintext(self, plaintext: bytes) -> bool:
        """Check if plaintext looks reasonable"""
        if len(plaintext) < 4 or len(plaintext) > 1000:
            return False
        
        # Check for reasonable ASCII content
        try:
            text = plaintext.decode('ascii', errors='strict')
            # Should have some printable characters
            printable_count = sum(1 for c in text if 32 <= ord(c) < 127)
            return printable_count >= len(text) * 0.7
        except UnicodeDecodeError:
            # Try UTF-8
            try:
                text = plaintext.decode('utf-8', errors='strict')
                return len(text) > 0
            except UnicodeDecodeError:
                return False
    
    def _try_suffix_pattern(self, n: int, e: int, c: int, suffix: bytes, unknown_len: int, log) -> Optional[bytes]:
        """Try to find message with known suffix"""
        if unknown_len > 24:  # Practical limit
            return None
        
        # Message form: X + suffix where X is unknown prefix
        suffix_int = bytes_to_long(suffix)
        suffix_bytes = len(suffix)
        
        # For small e and short suffix, try brute force approach
        if e <= 3 and unknown_len <= 16:
            for x in range(1 << (unknown_len * 8)):
                # Construct candidate message
                message_int = (x << (suffix_bytes * 8)) + suffix_int
                
                # Check if this encrypts to our ciphertext
                if pow(message_int, e, n) == c:
                    try:
                        candidate = long_to_bytes(message_int)
                        if candidate.endswith(suffix):
                            return candidate
                    except Exception:
                        continue
                
                # Early termination for performance
                if x > 100000:  # Practical limit
                    break
        
        return None
    
    def _try_padding_attack(self, n: int, e: int, c: int, log) -> Optional[bytes]:
        """Try attacks specific to e=3 with padding"""
        if e != 3:
            return None
        
        # Try PKCS#1 v1.5 padding format
        # Format: 0x00 0x02 [random padding] 0x00 [message]
        
        # For small messages, the padded result might be small enough
        # that m^3 < n, making it vulnerable to cube root attack
        
        try:
            # Try direct cube root
            if gmpy2:
                m, perfect = gmpy2.iroot(c, 3)
                if perfect:
                    candidate = long_to_bytes(int(m))
                    if self._looks_like_padded_message(candidate):
                        # Extract actual message from padding
                        extracted = self._extract_from_padding(candidate)
                        if extracted:
                            return extracted
            else:
                m = int(round(c ** (1.0/3)))
                if pow(m, 3) == c:
                    candidate = long_to_bytes(m)
                    if self._looks_like_padded_message(candidate):
                        extracted = self._extract_from_padding(candidate)
                        if extracted:
                            return extracted
        except Exception as ex:
            log.debug(f"[coppersmith] padding attack error: {ex}")
        
        return None
    
    def _looks_like_padded_message(self, data: bytes) -> bool:
        """Check if data looks like PKCS#1 v1.5 padded message"""
        if len(data) < 11:  # Minimum padding length
            return False
        
        # Check for PKCS#1 v1.5 format: 0x00 0x02 ...
        return data[0] == 0x00 and data[1] == 0x02
    
    def _extract_from_padding(self, padded_data: bytes) -> Optional[bytes]:
        """Extract actual message from PKCS#1 v1.5 padding"""
        if not self._looks_like_padded_message(padded_data):
            return None
        
        # Find the 0x00 separator
        try:
            separator_index = padded_data.index(b'\x00', 2)  # Start after 0x00 0x02
            if separator_index >= 10:  # Ensure minimum padding
                return padded_data[separator_index + 1:]
        except ValueError:
            pass
        
        return None



# ========= Attack helpers =========
def invmod(a: int, n: int) -> int:
    try:
        return pow(a, -1, n)
    except Exception:
        if gmpy2:
            inv = int(gmpy2.invert(a, n))
            if inv == 0:
                raise
            return inv
        raise

def bezout(a: int, b: int) -> Tuple[int, int]:
    # iterative extended gcd (non-recursive to avoid recursion depth)
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    # old_s * a + old_t * b = old_r (gcd)
    return old_s, old_t

def fermat_factor(n: int, max_steps: int = 100000) -> Tuple[Optional[int], Optional[int]]:
    if n % 2 == 0:
        return 2, n // 2
    a = int(gmpy2.isqrt(n)) if gmpy2 else int(math.isqrt(n))
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        b2 = a*a - n
        if b2 >= 0:
            b = int(gmpy2.isqrt(b2)) if gmpy2 else int(math.isqrt(b2))
            if b*b == b2:
                p = a - b
                q = a + b
                if p*q == n:
                    return p, q
        a += 1
    return None, None

def pollard_p1(n: int, B: int = 10000) -> Optional[int]:
    if n % 2 == 0:
        return 2
    a = 2
    for j in range(2, B):
        a = pow(a, j, n)
    g = math.gcd(a-1, n)
    if 1 < g < n:
        return g
    return None

def pollard_rho(n: int, max_tries: int = 5, max_iters: int = 200000) -> Optional[int]:
    if n % 2 == 0:
        return 2
    import random
    for _ in range(max_tries):
        x = random.randrange(2, n-1)
        y = x
        c = random.randrange(1, n-1)
        d = 1
        f = lambda v: (pow(v, 2, n) + c) % n
        for __ in range(max_iters):
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x-y), n)
            if d == 1:
                continue
            if d == n:
                break
            return d
    return None

def trial_division(n: int, limit: int = 200000) -> Optional[int]:
    if n % 2 == 0:
        return 2
    f = 3
    while f * f <= n and f <= limit:
        if n % f == 0:
            return f
        f += 2
    return None

def crt(remainders: List[int], moduli: List[int]) -> int:
    # simple CRT for pairwise-coprime moduli
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for (ai, mi) in zip(remainders, moduli):
        Ni = N // mi
        inv = invmod(Ni, mi)
        x = (x + ai * inv * Ni) % N
    return x

def contfrac(n, d):
    while d:
        a = n // d
        yield a
        n, d = d, n - a * d

def convergents(n, d):
    h1, h2 = 1, 0
    k1, k2 = 0, 1
    for a in contfrac(n, d):
        h = a*h1 + h2
        k = a*k1 + k2
        yield h, k
        h2, h1 = h1, h
        k2, k1 = k1, k

def wiener_attack(e, n) -> Optional[int]:
    for k, d in convergents(e, n):
        if k == 0:
            continue
        if (e*d - 1) % k != 0:
            continue
        phi = (e*d - 1) // k
        b = n - phi + 1
        disc = b*b - 4*n
        if disc >= 0:
            s = math.isqrt(disc)
            if s*s == disc:
                return d
    return None

# ========= Coppersmith Helpers =========
def coppersmith_univariate(poly_coeffs: List[int], n: int, beta: float = 1.0, epsilon: float = 0.01) -> Optional[int]:
    """
    Simplified Coppersmith method for univariate polynomials.
    poly_coeffs: coefficients [a0, a1, a2, ...] for a0 + a1*x + a2*x^2 + ...
    n: modulus
    beta: upper bound parameter (root < n^beta)
    Returns: small root if found, None otherwise
    """
    try:
        import numpy as np
    except ImportError:
        return None  # Skip if numpy not available
    
    degree = len(poly_coeffs) - 1
    if degree <= 0:
        return None
    
    # For small degree polynomials, use direct methods
    if degree == 1:
        # Linear: a0 + a1*x ≡ 0 (mod n)
        a0, a1 = poly_coeffs[0], poly_coeffs[1]
        if a1 == 0:
            return None
        try:
            x = (-a0 * invmod(a1, n)) % n
            # Check if this is actually small
            bound = int(n**beta)
            if x <= bound or (n - x) <= bound:
                return min(x, n - x)
        except Exception:
            pass
        return None
    
    elif degree == 2:
        # Quadratic: a0 + a1*x + a2*x^2 ≡ 0 (mod n)
        a0, a1, a2 = poly_coeffs[0], poly_coeffs[1], poly_coeffs[2]
        if a2 == 0:
            return coppersmith_univariate([a0, a1], n, beta, epsilon)
        
        # Use quadratic formula mod n
        try:
            # discriminant = b^2 - 4ac
            disc = (a1 * a1 - 4 * a0 * a2) % n
            
            # Try to find square root of discriminant
            if gmpy2:
                sqrt_disc = int(gmpy2.isqrt(disc))
                if pow(sqrt_disc, 2, n) != disc:
                    return None
            else:
                sqrt_disc = int(math.isqrt(disc))
                if pow(sqrt_disc, 2, n) != disc:
                    return None
            
            # Two solutions: x = (-b ± sqrt(disc)) / (2a)
            inv_2a = invmod(2 * a2, n)
            x1 = ((-a1 + sqrt_disc) * inv_2a) % n
            x2 = ((-a1 - sqrt_disc) * inv_2a) % n
            
            bound = int(n**beta)
            candidates = []
            
            for x in [x1, x2]:
                if x <= bound:
                    candidates.append(x)
                elif (n - x) <= bound:
                    candidates.append(n - x)
            
            if candidates:
                return min(candidates)
                
        except Exception:
            pass
        return None
    
    # For higher degrees, fall back to brute force within bound
    bound = min(100000, int(n**(beta + epsilon)))  # Practical limit
    
    def eval_poly(x):
        result = 0
        x_power = 1
        for coeff in poly_coeffs:
            result = (result + coeff * x_power) % n
            x_power = (x_power * x) % n
        return result
    
    for x in range(bound):
        if eval_poly(x) == 0:
            return x
    
    return None

def find_stereotyped_message(n: int, e: int, c: int, known_prefix: bytes, unknown_bytes: int = 16) -> Optional[bytes]:
    """
    Find message of form: known_prefix + unknown_suffix
    using Coppersmith attack for small unknown part.
    """
    if unknown_bytes > 20:  # Practical limit
        return None
    
    # Convert known prefix to integer
    prefix_int = bytes_to_long(known_prefix)
    
    # The message has form: M = prefix_int * 256^unknown_bytes + X
    # where X is the unknown part (X < 256^unknown_bytes)
    
    # We know: (prefix_int * 256^unknown_bytes + X)^e ≡ c (mod n)
    # Rearrange to polynomial in X
    
    shift = pow(256, unknown_bytes)
    known_part = prefix_int * shift
    
    # For small e, try direct approach
    if e <= 5:
        # Build polynomial coefficients for (known_part + X)^e - c ≡ 0 (mod n)
        coeffs = []
        
        # Binomial expansion of (a + x)^e = sum(C(e,k) * a^(e-k) * x^k)
        for k in range(e + 1):
            # Binomial coefficient C(e, k)
            binom_coeff = math.comb(e, k)
            # a^(e-k) where a = known_part
            a_power = pow(known_part, e - k, n)
            
            coeff = (binom_coeff * a_power) % n
            if k == 0:
                coeff = (coeff - c) % n  # Subtract c from constant term
            
            coeffs.append(coeff)
        
        # Try to find small root
        bound = pow(256, unknown_bytes)
        beta = math.log(bound) / math.log(n) if n > bound else 1.0
        
        x = coppersmith_univariate(coeffs, n, min(beta, 0.5))
        if x is not None and x < bound:
            try:
                # Reconstruct message
                message_int = known_part + x
                message_bytes = long_to_bytes(message_int)
                
                # Verify by encryption
                if pow(bytes_to_long(message_bytes), e, n) == c:
                    return message_bytes
            except Exception:
                pass
    
    return None


# ========= CLI / Engine =========
# tuned order: cheapest/fastest first (empirical), heavy ones later
ALL_ATTACKS = [
    KnownSumAttack(),
    SmallRootAttack(),
    SharedPrimePolynomialAttack(),
    SharedPrimeGCDAttack(),
    CommonModulusBezoutAttack(),
    WienerAttack(),
    CoppersmithAttack(),  # Added between Wiener (12) and TrialDivision (20)
    TrialDivisionAttack(),
    FactorDBAttack(),
    HastadsBroadcastAttack(),
    PollardP1Attack(),
    PollardRhoAttack(),
    PolynomialGuessAttack(),
    FermatAttack(),
]

# Est. durations (sec) used for progress display (informational only)
ESTIMATED_SECONDS = {
    "small_root": 0.5,
    "known_sum": 0.8,
    "sharedprime_gcd": 0.5,
    "common_modulus_bezout": 0.5,
    "wiener": 0.2,
    "coppersmith": 3.0,  # Added timing estimate
    "trial_division": 1.0,
    "pollard_rho": 60.0,
    "pollard_p1": 12.0,
    "hastads_broadcast": 4.0,
    "factordb": 1.0,
    "fermat": 10.0,
    "polynomial_guess" : 2.0,
}

# ----------------- new: parse file input -----------------
def _extract_pem_blocks(text: str) -> List[str]:
    """Return list of PEM blocks found in text (including BEGIN/END lines)."""
    blocks = []
    pem_re = re.compile(r'(-----BEGIN (?:PUBLIC|RSA PUBLIC) KEY-----.*?-----END (?:PUBLIC|RSA PUBLIC) KEY-----)', re.DOTALL)
    for m in pem_re.finditer(text):
        blocks.append(m.group(1).strip())
    return blocks

def _find_keyvals_in_text(text: str) -> List[Tuple[str, str, int]]:
    """
    Ultra-flexible parser for key-value pairs. Supports:
    - Various separators: =, :, ->, =>, |, space
    - Comments: #, //, /* */
    - Quoted values: "...", '...'
    - Multi-line values
    - JSON-like syntax: {"n": "123"}
    - Variable names with any characters
    """
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        
        # Skip empty lines and PEM blocks
        if not ln or ln.startswith("-----BEGIN") or ln.startswith("-----END"):
            i += 1
            continue
            
        # Skip comments
        if ln.startswith("#") or ln.startswith("//") or ln.startswith("/*"):
            i += 1
            continue
        
        # Try multiple parsing patterns (most flexible first)
        patterns = [
            # Standard: name = value, name: value
            r'\s*([A-Za-z0-9_\-\.]+)\s*[:=]\s*(.+)$',
            # Arrow style: name -> value, name => value  
            r'\s*([A-Za-z0-9_\-\.]+)\s*[-=]>\s*(.+)$',
            # Pipe style: name | value
            r'\s*([A-Za-z0-9_\-\.]+)\s*\|\s*(.+)$',
            # Space separated: name value (if value looks like number/hex)
            r'\s*([A-Za-z0-9_\-\.]+)\s+([0-9A-Fa-fxX\+\=/]{4,})\s*$',
            # JSON-like: "name": "value"
            r'\s*["\']?([A-Za-z0-9_\-\.]+)["\']?\s*[:]\s*["\']?([^"\',}]+)["\']?',
            # Loose match: any word followed by potential value
            r'\s*([A-Za-z0-9_\-\.]+)[^A-Za-z0-9]*([0-9A-Fa-fxX\+\=/]{8,}).*$'
        ]
        
        matched = False
        for pattern in patterns:
            m = re.match(pattern, ln)
            if m:
                name = m.group(1).strip()
                val = m.group(2).strip()
                
                # Clean up value (remove quotes, trailing punctuation)
                val = re.sub(r'^["\'](.+)["\']$', r'\1', val)  # Remove quotes
                val = re.sub(r'[,;\s]*$', '', val)  # Remove trailing punctuation
                
                # Handle multi-line values (if next line looks like continuation)
                j = i + 1
                while j < len(lines) and lines[j].strip() and not re.match(r'^\s*[A-Za-z0-9_\-\.]+\s*[:=]', lines[j]):
                    continuation = lines[j].strip()
                    if continuation and not continuation.startswith('#'):
                        val += ' ' + continuation
                    j += 1
                i = j - 1  # Update loop counter
                
                if name and val:
                    out.append((name, val, i+1))
                    matched = True
                    break
        
        # If no pattern matched, try to extract any number sequences
        if not matched:
            # Look for standalone numbers that might be values
            numbers = re.findall(r'(?:0x)?[0-9A-Fa-f]{8,}', ln)
            if numbers and len(numbers) <= 3:  # Likely n, e, c
                # Create synthetic names
                for idx, num in enumerate(numbers):
                    synthetic_name = ['n', 'e', 'c'][idx] if idx < 3 else f'value{idx}'
                    out.append((synthetic_name, num, i+1))
        
        i += 1
    
    return out

def parse_input_file(path: str, log) -> Tuple[List[PubKey], List[int]]:
    """
    Parse a file that may contain:
      - PEM blocks (BEGIN PUBLIC KEY)
      - key-value lines n=/e=/c=/ciphertext=/Encrypted=
      - comma- or space-separated multiple values for any key
      - numbered variables (n1,n2,e_1,e-2,c1,...)
      - groups separated by blank lines
    Returns (keys_list, ciphers_list)
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    txt = open(path, "r", encoding="utf-8", errors="ignore").read()

    keys: List[PubKey] = []
    c_list: List[int] = []

    # 0) Try JSON parsing first (structured data)
    try:
        import json
        json_data = json.loads(txt)
        if isinstance(json_data, dict):
            # Single object with RSA parameters
            n_val = json_data.get('n') or json_data.get('modulus') or json_data.get('N')
            e_val = json_data.get('e') or json_data.get('exponent') or json_data.get('E') or 65537
            c_val = json_data.get('c') or json_data.get('ciphertext') or json_data.get('encrypted')
            x_val = json_data.get('x') or json_data.get('sum')
            
            if n_val and e_val:
                try:
                    n_int = parse_int_auto(str(n_val)) if isinstance(n_val, str) else int(n_val)
                    e_int = parse_int_auto(str(e_val)) if isinstance(e_val, str) else int(e_val)
                    extras = {}
                    if x_val:
                        extras['x'] = str(x_val)
                    keys.append(PubKey(n=n_int, e=e_int, label=f"{os.path.basename(path)}:json", extras=extras if extras else None))
                    
                    if c_val:
                        c_int = parse_cipher_auto(str(c_val))
                        c_list.append(c_int)
                        
                except Exception as ex:
                    log.debug(f"JSON parsing failed for single object: {ex}")
                    
        elif isinstance(json_data, list):
            # Array of RSA parameter objects
            for i, item in enumerate(json_data):
                if isinstance(item, dict):
                    try:
                        n_val = item.get('n') or item.get('modulus')
                        e_val = item.get('e') or item.get('exponent') or 65537
                        c_val = item.get('c') or item.get('ciphertext')
                        
                        if n_val:
                            n_int = parse_int_auto(str(n_val)) if isinstance(n_val, str) else int(n_val)
                            e_int = parse_int_auto(str(e_val)) if isinstance(e_val, str) else int(e_val)
                            keys.append(PubKey(n=n_int, e=e_int, label=f"{os.path.basename(path)}:json#{i}"))
                            
                            if c_val:
                                c_int = parse_cipher_auto(str(c_val))
                                c_list.append(c_int)
                    except Exception as ex:
                        log.debug(f"JSON parsing failed for item {i}: {ex}")
                        
        # If JSON parsing succeeded, return early
        if keys or c_list:
            log.debug(f"Successfully parsed JSON: {len(keys)} keys, {len(c_list)} ciphers")
            return keys, c_list
            
    except json.JSONDecodeError:
        # Not valid JSON, continue with other parsing methods
        pass
    except Exception as ex:
        log.debug(f"JSON parsing error: {ex}")

    # 1) extract and load any PEM public keys in file
    pem_blocks = _extract_pem_blocks(txt)
    for i, pem in enumerate(pem_blocks):
        try:
            key = RSA.import_key(pem.encode())
            keys.append(PubKey(n=int(key.n), e=int(key.e), label=f"{os.path.basename(path)}:pem#{i}"))
            log.debug(f"Loaded PEM from file: n={int(key.n)} e={int(key.e)}")
        except Exception as ex:
            log.debug(f"Could not import PEM block in {path}: {ex}")

    # 2) find assignments
    kvs = _find_keyvals_in_text(txt)

    # if empty kvs -> nothing more to parse
    if not kvs:
        return keys, c_list

    # helper: split comma/space-separated multi-values
    def _split_multi(val: str) -> List[str]:
        # replace newlines and split on commas or whitespace, preserve tokens like "0x..." or base64
        cleaned = val.replace("\r", " ").replace("\n", " ")
        parts = re.split(r"[,\s]+", cleaned.strip())
        return [p.strip() for p in parts if p.strip()]

    # Determine whether numbered style is used anywhere (n1 / e_1 / c1)
    numbered = False
    for name, _, _ in kvs:
        if re.search(r'\d', name):
            numbered = True
            break

    if numbered:
        # group by numeric index found at end of name (e.g., n1, e_2, cipher3)
        groups: Dict[int, Dict[str, List[str]]] = {}
        for name, val, _ in kvs:
            # split base name and index (digits at end possibly with underscore/dash)
            m = re.match(r'^([A-Za-z_]+?)[_\-]?(\d+)$', name)
            if m:
                base = m.group(1).lower()
                idx = int(m.group(2))
            else:
                # no trailing digits -> treat as index 0 (global)
                base = name.lower()
                idx = 0
            # support multi-valued right-hand sides
            for item in _split_multi(val):
                groups.setdefault(idx, {}).setdefault(base, []).append(item)

        # Gather global attributes (index 0) for fallback
        global_group = groups.get(0, {})
        # parse global n and e if present
        global_n = None
        if 'n' in global_group and global_group['n']:
            try:
                global_n = parse_int_auto(global_group['n'][0])
            except Exception:
                try:
                    global_n = int(global_group['n'][0], 16)
                except Exception:
                    global_n = None

        global_e = None
        if 'e' in global_group and global_group['e']:
            try:
                global_e = parse_int_auto(global_group['e'][0])
            except Exception:
                try:
                    global_e = int(global_group['e'][0], 16)
                except Exception:
                    global_e = None

        # now for each numeric index create entries (skip index 0 here)
        for idx in sorted(k for k in groups.keys() if k != 0):
            g = groups[idx]
            # pick n: prefer per-index n, otherwise fall back to global_n (if exists)
            n_token = None
            if 'n' in g and g['n']:
                n_token = g['n'][0]
            elif global_n is not None:
                # represent global_n as string so we parse uniformly below
                n_token = str(global_group.get('n')[0])

            # pick e: prefer per-index e, otherwise fall back to global_e (if exists)
            e_token = None
            if 'e' in g and g['e']:
                e_token = g['e'][0]
            elif global_e is not None:
                e_token = str(global_group.get('e')[0])

            # collect cipher variants for this index (support multiple names)
            cipher_vals: List[str] = []
            for cname in ('c', 'c1', 'ciphertext', 'cipher', 'encrypted', 'enc'):
                if cname in g:
                    cipher_vals.extend(g[cname])

            # also include any key named something-with-digits that looks like ciphertext
            for kn, vals in g.items():
                if kn not in ('n', 'e', 'c', 'c1', 'ciphertext', 'cipher', 'encrypted', 'enc'):
                    # if key contains digits but isn't pure letters, consider its values as candidate ciphers
                    if re.search(r'\d', kn):
                        for v in vals:
                            if re.fullmatch(r'[0-9A-Fa-fxX\+\=/]+', v):
                                cipher_vals.append(v)

            # parse numeric n if present (either per-index or global fallback)
            if n_token:
                try:
                    n_val = parse_int_auto(n_token)
                except Exception:
                    try:
                        n_val = int(n_token, 16)
                    except Exception:
                        n_val = None
                if n_val is not None:
                    # parse e
                    if e_token:
                        try:
                            e_val = parse_int_auto(e_token)
                        except Exception:
                            try:
                                e_val = int(e_token, 16)
                            except Exception:
                                e_val = None
                    else:
                        e_val = global_e if global_e is not None else 65537

                    # finally append PubKey
                    keys.append(PubKey(n=n_val, e=e_val, label=f"{os.path.basename(path)}:idx{idx}"))

                    # attach any ciphers for this index (support multi-values)
                    for cv in cipher_vals:
                        for sub in _split_multi(cv):
                            try:
                                c_list.append(parse_cipher_auto(sub))
                            except Exception:
                                pass
            else:
                # no n provided for this idx: still append ciphers if present
                for cv in cipher_vals:
                    for sub in _split_multi(cv):
                        try:
                            c_list.append(parse_cipher_auto(sub))
                        except Exception:
                            pass

        # also handle any global-only ciphers (index 0)
        if 0 in groups:
            g0 = groups[0]
            for cname in ('c', 'c1', 'ciphertext', 'cipher', 'encrypted', 'enc'):
                if cname in g0:
                    for cv in g0[cname]:
                        for sub in _split_multi(cv):
                            try:
                                c_list.append(parse_cipher_auto(sub))
                            except Exception:
                                pass

        return keys, c_list

    # else: non-numbered style -> split text into groups by blank lines and parse each group
    groups_text = [g.strip() for g in re.split(r'\n\s*\n', txt) if g.strip()]
    for gidx, gtext in enumerate(groups_text):
        # skip if group contains only PEM block (already handled)
        if '-----BEGIN' in gtext and '-----END' in gtext:
            # maybe there's PEM plus a following c= line in same group -> we still parse kvs inside
            pass
        # gather kvs in this group
        group_kvs = _find_keyvals_in_text(gtext)
        if not group_kvs:
            continue
        n_token = None
        e_token = None
        x_token = None
        cipher_vals: List[str] = []
        # support multi-valued RHSs by flattening them into tokens
        group_n_tokens: List[str] = []
        group_e_tokens: List[str] = []
        group_c_tokens: List[str] = []

        for name, val, _ in group_kvs:
            lname = name.lower()
            # split RHS into multiple possible tokens
            tokens = _split_multi(val)
            
            # Ultra-flexible variable name recognition
            def is_n_like(name_str):
                """Check if variable name refers to modulus n"""
                patterns = ['n', 'modulus', 'mod', 'public_key', 'pubkey', 'pk', 'rsa_n', 'modulo']
                return any(pattern in name_str for pattern in patterns) or name_str.startswith('n')
            
            def is_e_like(name_str):
                """Check if variable name refers to exponent e"""
                patterns = ['e', 'exp', 'exponent', 'public_exp', 'pub_exp', 'rsa_e', 'key_exp']
                return any(pattern in name_str for pattern in patterns) or name_str.startswith('e')
            
            def is_c_like(name_str):
                """Check if variable name refers to ciphertext c"""
                patterns = ['c', 'cipher', 'ciphertext', 'encrypted', 'enc', 'cyphertext', 
                           'message', 'msg', 'ct', 'crypto', 'secret', 'flag', 'output']
                return any(pattern in name_str for pattern in patterns) or name_str.startswith('c')
            
            def is_x_like(name_str):
                """Check if variable name refers to sum/difference x"""
                patterns = ['x', 'sum', 's', 'diff', 'difference', 'p_plus_q', 'p+q', 'pq_sum']
                return any(pattern in name_str for pattern in patterns)
            
            # Classify variable based on flexible matching
            if is_n_like(lname):
                group_n_tokens.extend(tokens)
            elif is_e_like(lname):
                group_e_tokens.extend(tokens)
            elif is_x_like(lname):
                x_token = val
            elif is_c_like(lname):
                group_c_tokens.extend(tokens)
            else:
                # Final fallback: if value looks like a large number, guess type by position/context
                if len(tokens) == 1 and len(tokens[0]) > 10:
                    val_str = tokens[0]
                    # If it's a really large number (>100 digits), probably modulus n
                    if len(val_str) > 100 or 'modulus' in lname or 'public' in lname:
                        group_n_tokens.extend(tokens)
                    # If small number, probably exponent e
                    elif len(val_str) < 10 and val_str.isdigit():
                        group_e_tokens.extend(tokens)
                    # Otherwise, assume ciphertext
                    else:
                        group_c_tokens.extend(tokens)

        # Now handle sequences: if there are multiple n/e/c tokens in the group,
        # pair them positionally; if counts differ, missing entries default to None/e=65537.
        max_len = max(len(group_n_tokens), len(group_e_tokens), len(group_c_tokens))
        if max_len == 0:
            continue

        for i in range(max_len):
            n_val = None
            if i < len(group_n_tokens):
                try:
                    n_val = parse_int_auto(group_n_tokens[i])
                except Exception:
                    try:
                        n_val = int(group_n_tokens[i], 16)
                    except Exception:
                        n_val = None
            e_val = None
            if i < len(group_e_tokens):
                try:
                    e_val = parse_int_auto(group_e_tokens[i])
                except Exception:
                    try:
                        e_val = int(group_e_tokens[i], 16)
                    except Exception:
                        e_val = None
            if e_val is None:
                e_val = 65537

            if n_val is not None:
                extras = {}
                if x_token:
                    extras['x'] = x_token
                keys.append(PubKey(n=n_val, e=e_val, label=f"{os.path.basename(path)}:g{gidx}", extras=extras if extras else None))

            # cipher token at same position appended as ciphertext
            if i < len(group_c_tokens):
                try:
                    c_list.append(parse_cipher_auto(group_c_tokens[i]))
                except Exception:
                    pass

    return keys, c_list


# ----------------- end parse file input -----------------


def parse_args():
    # build dynamic attack list for help
    attack_names = ", ".join(a.name for a in sorted(ALL_ATTACKS, key=lambda x: x.priority))
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""
Examples:                            
  python3 rsaxploit.py --publickey pub1.pem,pub2.pem --decrypt "c1,c2"
  python3 rsaxploit.py -n "N1,N2" -e "3,65537" --decrypt "C1,C2"
  python3 rsaxploit.py -n N -e 65537 --decrypt C --flag-format "FLAG\\{{.*?\\}}"

Available attacks: [{attack_names}]

Also you may pass a single filename argument (e.g. cipher.txt) [n = , c1 = ,c2 =, e = ,pubkey,... inside]\n
Example : {Colors.YELLOW}{Colors.BOLD}python3 rsaxploit.py cipher.txt{Colors.RESET}  

To test all attacks: {Colors.YELLOW}{Colors.BOLD}./test.sh{Colors.RESET}
""")
    )
    p.add_argument("--publickey", help="PEM path(s), comma-separated or wildcard", default=None)
    p.add_argument("-n", nargs="+", help="modulus N (dec/hex) or comma-separated list", default=None)
    p.add_argument("-e", nargs="+", help="exponent e (dec/hex) or comma-separated list", default=None)
    p.add_argument("--decrypt", nargs="+", help="ciphertext(s) dec/hex/base64, comma-separated or space-separated", default=None)
    p.add_argument("--attack", help="limit to one or more attacks (comma-separated)", default=None)
    p.add_argument("--flag-format", help="regex for stopping when plaintext matches", default=None)
    p.add_argument("--no-stop", action="store_true", help="do not stop on first success")
    p.add_argument("--verbosity", choices=["DEBUG", "INFO", "WARN", "ERROR"], default="INFO")
    # positional optional file argument
    p.add_argument("infile", nargs="?", help="optional input filename (e.g. cipher.txt) to parse keys/ciphers from", default=None)
    return p.parse_args()

def expand_publickeys(spec: str) -> List[str]:
    paths = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if any(ch in token for ch in "*?[]"):
            import glob
            paths.extend(glob.glob(token))
        else:
            paths.append(token)
    # unique preserve order
    seen = set()
    out = []
    for p in paths:
        if p not in seen:
            seen.add(p); out.append(p)
    return out

def load_keys_from_pem(paths: List[str], log) -> List[PubKey]:
    out = []
    for p in paths:
        try:
            raw = open(p, "rb").read()
            key = RSA.import_key(raw)
            out.append(PubKey(n=int(key.n), e=int(key.e), label=os.path.basename(p)))
        except Exception as ex:
            log.warning(f"Could not parse PEM {p}: {ex}")
    return out

def make_keys_from_ne(n_tokens: List[str], e_tokens: Optional[List[str]], log) -> List[PubKey]:
    Ns = [parse_int_auto(t) for t in n_tokens] if n_tokens else []
    Es = [parse_int_auto(t) for t in e_tokens] if e_tokens else []

    if not Ns:
        return []
    if not Es:
        Es = [65537]

    target = max(len(Ns), len(Es))
    def expand(arr, L):
        if len(arr) == L:
            return arr
        if len(arr) == 1:
            return arr * L
        if len(arr) < L:
            return arr + [arr[0]]*(L - len(arr))
        return arr[:L]
    Ns = expand(Ns, target)
    Es = expand(Es, target)

    keys = []
    for i, (n, e) in enumerate(zip(Ns, Es)):
        keys.append(PubKey(n=n, e=e, label=f"N#{i}"))
        log.debug(f"Loaded key {i}: n={n}, e={e}")
    return keys

def pick_attacks(only: Optional[str]) -> List[Attack]:
    if not only:
        return sorted(ALL_ATTACKS, key=lambda a: a.priority)
    wanted = [x.strip().lower() for x in only.split(",")]
    table = {a.name.lower(): a for a in ALL_ATTACKS}
    chosen = []
    for w in wanted:
        if w in table:
            chosen.append(table[w])
    return sorted(chosen, key=lambda a: a.priority)

def try_decode(pt: bytes) -> str:
    try:
        return pt.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ---------- Progress / threading wrapper ----------
class _AttackRunnerThread(threading.Thread):
    def __init__(self, attack: Attack, keys, c_list, args, log):
        super().__init__(daemon=True)
        self.attack = attack
        self.keys = keys
        self.c_list = c_list
        self.args = args
        self.log = log
        self.result: Optional[AttackResult] = None
        self.exc: Optional[Exception] = None

    def run(self):
        try:
            res = self.attack.run(self.keys, self.c_list, self.args, self.log)
            self.result = res
        except Exception as ex:
            self.exc = ex
            self.result = AttackResult(self.attack.name, False, info=f"error:{type(ex).__name__}")

def _display_progress_loop(atk_name: str, est_seconds: float, thread: _AttackRunnerThread, stop_event: threading.Event):
    """
    Show a single-line progress bar while thread is running.
    If attack runs longer than est_seconds, switch to overrun spinner with elapsed seconds.
    stop_event can be set to stop display early (skip).
    """
    width = 28
    start = time.time()
    spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    sp_i = 0
    try:
        while thread.is_alive() and not stop_event.is_set():
            elapsed = time.time() - start
            if est_seconds and est_seconds > 0 and elapsed <= est_seconds:
                frac = min(1.0, elapsed / est_seconds)
                filled = int(frac * width)
                bar = "[" + "#" * filled + "-" * (width - filled) + "]"
                pct = int(frac * 100)
                eta = max(0, est_seconds - elapsed)
                sys.stdout.write(f"\r{Colors.DIM}{atk_name:20} {bar} {pct:3d}% ETA:{int(eta):3d}s{Colors.RESET}")
            else:
                # overrun / spinner mode
                ch = spinner[sp_i % len(spinner)]
                sys.stdout.write(f"\r{Colors.DIM}{atk_name:20} {ch} running... {int(elapsed):3d}s{Colors.RESET}")
                sp_i += 1
            sys.stdout.flush()
            time.sleep(0.18)
        # final clear
        sys.stdout.write("\r" + " " * (80) + "\r")
        sys.stdout.flush()
    except Exception:
        # progress display should never crash
        try:
            sys.stdout.write("\r" + " " * (80) + "\r"); sys.stdout.flush()
        except Exception:
            pass

# ---------- End progress wrapper ----------


def main():
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.verbosity), format="%(message)s")
    log = logging.getLogger("rsaxploit")

    print(banner())
    log.info(f"{Colors.CYAN}RsaXploit starting...{Colors.RESET}")

    # Keys
    keys: List[PubKey] = []
    # load from --publickey if given
    if args.publickey:
        paths = expand_publickeys(args.publickey)
        keys.extend(load_keys_from_pem(paths, log))

    # If positional filename provided, parse it
    if args.infile:
        try:
            file_keys, file_ciphers = parse_input_file(args.infile, log)
            if file_keys:
                # prefer file keys first
                keys.extend(file_keys)
            # append file ciphers to c_list later
        except Exception as ex:
            log.error(f"Failed to parse input file {args.infile}: {ex}")
            sys.exit(1)

    # -n/-e now accept either "N1,N2" or "N1 N2" forms
    n_tokens = split_arg_tokens(args.n)
    e_tokens = split_arg_tokens(args.e)
    if n_tokens:
        keys.extend(make_keys_from_ne(n_tokens, e_tokens, log))

    if not keys:
        log.error(Colors.RED + "No public keys provided. Use --publickey or -n/-e or provide an input file." + Colors.RESET)
        sys.exit(1)

    # Ciphers
    c_list: List[int] = []
    # 1) from --decrypt CLI
    if args.decrypt:
        try:
            c_list = parse_ciphers_from_arg(args.decrypt)
        except Exception as ex:
            log.error(f"Failed to parse --decrypt: {ex}")
            sys.exit(1)
    # 2) if infile present attempt to grab parsed ciphers (append)
    if args.infile:
        try:
            file_keys, file_ciphers = parse_input_file(args.infile, log)
            if file_ciphers:
                # append file ciphers after CLI ones
                c_list.extend(file_ciphers)
        except Exception:
            pass

    # nice input summary (one-line)
    attacks_desc = "all" if not args.attack else args.attack
    stop_on_hit = "no" if args.no_stop else "yes"
    summary_row = f"Public keys: {len(keys)} | Ciphertexts: {len(c_list)} | Attacks: {attacks_desc} | Stop on hit: {stop_on_hit}"
    print(box("INPUT SUMMARY", [summary_row]))

    # Attacks
    attacks = pick_attacks(args.attack)

    # Run
    summary: List[Tuple[str, bool, str, float]] = []
    results_map: Dict[str, AttackResult] = {}
    found_plaintext: Optional[bytes] = None
    found_by: Optional[str] = None
    found_d: Optional[int] = None
    found_pq: Optional[Tuple[int, int]] = None

    for atk in attacks:
        if not atk.can_run(keys, c_list, args):
            # skip silently (not supported in this input combination)
            continue

        est = ESTIMATED_SECONDS.get(atk.name.lower(), 5.0)
        t0 = time.time()
        runner = _AttackRunnerThread(atk, keys, c_list, args, log)
        stop_event = threading.Event()

        # start thread
        runner.start()

        # start progress display in main thread while attack runs
        try:
            # display until thread finishes or user requests skip
            _display_progress_loop(atk.name, est, runner, stop_event)

            # Wait for thread to finish (join with small timeout to be responsive to CTRL+C)
            while runner.is_alive():
                try:
                    runner.join(timeout=0.2)
                except KeyboardInterrupt:
                    # User pressed Ctrl+C -> skip this attack
                    stop_event.set()
                    dt_skip = time.time() - t0
                    summary.append((atk.name, False, "skipped", dt_skip))
                    print(one_line(None, atk.name, dt_skip))
                    # Let attack thread continue in background; ignore its result.
                    break
            # if we set skip, proceed to next attack
            if stop_event.is_set():
                continue
            # otherwise get result
            if runner.exc:
                res = runner.result if runner.result is not None else AttackResult(atk.name, False, info=f"error:{type(runner.exc).__name__}")
            else:
                res = runner.result if runner.result is not None else AttackResult(atk.name, False, info="no-result")
        except KeyboardInterrupt:
            # If user interrupts outside the display loop, skip current attack
            stop_event.set()
            dt_skip = time.time() - t0
            summary.append((atk.name, False, "skipped", dt_skip))
            print(one_line(None, atk.name, dt_skip))
            continue
        except Exception as ex:
            log.debug(f"[{atk.name}] progress/display error: {ex}")
            res = AttackResult(atk.name, False, info=f"error:{type(ex).__name__}")

        dt = time.time() - t0
        results_map[atk.name] = res
        summary.append((atk.name, res.success, res.info, dt))
        print(one_line(res.success, atk.name, dt))

        if res.success and res.plaintext is not None and found_plaintext is None:
            found_plaintext = res.plaintext
            found_by = res.name
            found_d = res.recovered_d
            found_pq = res.recovered_pq

            # enhanced outputs: show multiple formats
            if args.flag_format:
                txt = try_decode(found_plaintext)
                if re.search(args.flag_format, txt or ""):
                    break
            if not args.no_stop:
                break

    # Summary box
    lines = []
    header = f"{'Attack':<22} | {'Result':^6} | {'UTF-8 (trimmed)':<48} | {'Time'}"
    lines.append(header)
    lines.append("-" * max(60, len(header)))
    for name, ok, note, dt in summary:
        result = "OK" if ok else "NO"
        u8_display = ""
        # if we stored the AttackResult for this attack, try to show its plaintext
        res = results_map.get(name)
        if res and res.success and res.plaintext is not None:
            try:
                # decode utf-8 (ignore errors), replace newlines with spaces, trim
                s = res.plaintext.decode('utf-8', errors='ignore').strip()
                s = re.sub(r'\s+', ' ', s)
                if len(s) > 45:
                    s = s[:45] + "..."
                u8_display = s
            except Exception:
                # show a short hex prefix if not decodable
                try:
                    hx = res.plaintext.hex()
                    u8_display = hx[:44] + ("..." if len(hx) > 44 else "")
                except Exception:
                    u8_display = "(binary)"
        else:
            u8_display = "-"
        lines.append(f"{name:<22} | {result:^6} | {u8_display:<48} | {dt:>5.2f}s")
    print()
    print(box("ATTACK SUMMARY", lines))


    # Results (extended formatting)
    print()
    if found_plaintext is not None:
        pt_bytes = found_plaintext if isinstance(found_plaintext, (bytes, bytearray)) else None
        pt_str = try_decode(found_plaintext) if pt_bytes else ""
        print(Colors.GREEN + Colors.BOLD + "🎯 Plaintext recovered!" + Colors.RESET)
        print(f"{Colors.BOLD}{Colors.CYAN}By:{Colors.RESET}    {found_by}")
        print(f"{Colors.BOLD}{'-'*40}{Colors.RESET}")
        # UTF-8 display (best-effort)
        if pt_bytes:
            print(f"{Colors.BOLD}{Colors.GREEN}UTF-8:  {pt_str}{Colors.RESET}")
        else:
            print(f"{Colors.BOLD}{Colors.GREEN}UTF-8:  (not bytes){Colors.RESET}")
        print(f"{Colors.BOLD}{'-'*40}{Colors.RESET}")

        # Hex (always show)
        if pt_bytes:
            print(f"{Colors.BOLD}Hex:{Colors.RESET}   {pt_bytes.hex()}")
        else:
            print(f"{Colors.BOLD}Hex:{Colors.RESET}   (not bytes)")

        # UTF-16 attempt
        if pt_bytes:
            try:
                u16 = pt_bytes.decode('utf-16', errors='ignore')
                print(f"{Colors.BOLD}UTF-16:{Colors.RESET} {u16}")
            except Exception:
                pass

        # Printable ASCII
        if pt_bytes and is_printable_bytes(pt_bytes):
            try:
                ascii_s = pt_bytes.decode('ascii', errors='ignore')
                print(f"{Colors.BOLD}ASCII:{Colors.RESET}  {ascii_s}")
            except Exception:
                pass

        # integer representation
        # if pt_bytes:
        #     try:
        #         # Convert to integer (big-endian)
        #         integer_val = int.from_bytes(pt_bytes, 'big')
        #         print(f"{Colors.BOLD}Int:{Colors.RESET}    {integer_val}")

        #         # Little-endian representation
        #         little_endian_bytes = pt_bytes[::-1]  # reverse the bytes
        #         print(f"{Colors.BOLD}Int:{Colors.RESET}  {little_endian_bytes.hex()}[Little Endian]")

        #     except Exception:
        #         pass


        if found_pq:
            p, q = found_pq
            print(f"{Colors.BOLD}p:{Colors.RESET}     {p}")
            print(f"{Colors.BOLD}q:{Colors.RESET}     {q}")
        if found_d:
            print(f"{Colors.BOLD}d:{Colors.RESET}     {found_d}")
        print()
    else:
        print(Colors.RED + Colors.BOLD + "❌ No plaintext recovered." + Colors.RESET)
        print()

    log.info(Colors.CYAN + "All selected attacks finished." + Colors.RESET)


# ========= Entrypoint =========
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # If KeyboardInterrupt escapes main (e.g., user pressed Ctrl+C outside an attack),
        # show a friendly message and exit.
        print("\n" + Colors.RED + "Interrupted by user." + Colors.RESET)
        sys.exit(130)
