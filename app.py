"""Interactive weak-RSA attack visualizer.

A Streamlit front-end over the `weakrsa` package: dial in a weakness, generate a
real RSA key (or a fleet of them), then *watch* the attack recover the secret
step by step. Run with:

    streamlit run app.py

The attack logic lives in weakrsa/ and is unchanged; this file only drives and
draws it.
"""

from __future__ import annotations

import time

import streamlit as st

from weakrsa import keygen
from weakrsa.attacks import batch_gcd, fermat, hastad, wiener
from weakrsa.utils import modinv

st.set_page_config(page_title="Weak RSA — Attack Visualizer", page_icon="🔓", layout="wide")

def fingerprint(n: int) -> str:
    """Short, readable fingerprint of a big modulus."""
    h = hex(n)[2:]
    return f"{h[:8]}…{h[-6:]}"


# ========================================================================== #
#  Attack page: Batch GCD
# ========================================================================== #
def page_batch_gcd() -> None:
    st.title("🔓 Batch GCD — low-entropy RNG")
    st.caption(
        "A fleet of devices with a weak boot-time RNG reuses primes across keys. "
        "If two public moduli share a prime, `gcd(Nᵢ, Nⱼ)` reveals it and both "
        "keys fall — the *Mind your Ps and Qs* attack."
    )

    # ---- controls ---------------------------------------------------------- #
    with st.sidebar:
        st.header("Fleet settings")
        bits = st.selectbox("Key size (bits)", [256, 512, 1024, 2048], index=1,
                            help="2048 = real-size. Attack is size-independent; smaller keeps the demo snappy.")
        count = st.slider("Number of devices", 10, 100, 40)
        entropy = st.slider("RNG entropy (distinct 1st primes)", 3, 300, 12,
                           help="Distinct values p can take. Set it far above the device "
                                "count for few/no collisions; the 'fix' panel shows a truly random RNG.")
        seed = st.number_input("RNG seed", value=1234, step=1)
        gen = st.button("🏭 Generate fleet", type="primary", use_container_width=True)
        st.divider()
        speed = st.slider("Animation speed", 1, 20, 8)

    # ---- (re)generate the fleet ------------------------------------------- #
    if gen or "bg_farm" not in st.session_state:
        with st.spinner(f"Generating {count} keys at {bits}-bit…"):
            farm = keygen.low_entropy_farm(count=count, bits=bits,
                                           entropy_primes=entropy, seed=int(seed))
            found = batch_gcd.batch_gcd(farm.moduli)
            frames = list(batch_gcd.iter_pairwise(farm.moduli))
            # first frame index at which each key is revealed as broken
            reveal_at: dict[int, int] = {}
            for idx, fr in enumerate(frames):
                if fr["collision"]:
                    reveal_at.setdefault(fr["i"], idx)
                    reveal_at.setdefault(fr["j"], idx)
            # the "fix" demonstration, computed once here (not on every rerun)
            safe_n = min(count, 25)
            safe_mods = [keygen.safe_key(bits=bits).n for _ in range(safe_n)]
            st.session_state.bg_fix = (len(batch_gcd.batch_gcd(safe_mods)), safe_n)
        st.session_state.bg_farm = farm
        st.session_state.bg_found = found
        st.session_state.bg_frames = frames
        st.session_state.bg_reveal_at = reveal_at
        st.session_state.bg_step = 0
        st.session_state.bg_playing = False

    farm = st.session_state.bg_farm
    frames = st.session_state.bg_frames
    found = st.session_state.bg_found
    reveal_at = st.session_state.bg_reveal_at
    total = len(frames)

    # Broken keys are all green. We still group keys that share a prime and tag
    # each with a small group number, so "which keys collided" stays visible.
    cluster = batch_gcd.clusters(farm.moduli, found)
    key_group: dict[int, int] = {}
    for gi, p in enumerate(sorted(cluster), start=1):
        for idx in cluster[p]:
            key_group[idx] = gi
    BROKEN_COLOR = "#2e7d32"  # green
    LOCKED_COLOR = "#2b2b2b"  # grey

    # ---- transport controls ---------------------------------------------- #
    c1, c2, c3, c4 = st.columns([1, 1, 1, 3])
    if c1.button("▶ Play", use_container_width=True):
        st.session_state.bg_playing = True
    if c2.button("⏭ Step", use_container_width=True):
        st.session_state.bg_playing = False
        st.session_state.bg_step = _advance_to_next_collision(
            frames, st.session_state.bg_step)
    if c3.button("⏮ Reset", use_container_width=True):
        st.session_state.bg_playing = False
        st.session_state.bg_step = 0
    if c4.button("⏩ Run to end", use_container_width=True):
        st.session_state.bg_playing = False
        st.session_state.bg_step = total

    step = st.session_state.bg_step
    cur = frames[step - 1] if 0 < step <= total else None

    # ---- live metrics ----------------------------------------------------- #
    checked = step
    collisions = sum(1 for f in frames[:step] if f["collision"])
    broken = sum(1 for idx in reveal_at if reveal_at[idx] < step)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Pairs checked", f"{checked:,} / {total:,}")
    m2.metric("Collisions found", collisions)
    m3.metric("Keys broken", f"{broken} / {len(farm.keys)}")
    m4.metric("Fleet broken", f"{100*broken/len(farm.keys):.0f}%")
    st.progress(step / total if total else 0.0)

    if cur is not None and cur["collision"]:
        i, j = cur["i"], cur["j"]
        st.success(
            f"💥 Collision! `gcd(N{i}, N{j})` = shared prime "
            f"`{fingerprint(cur['gcd'])}` → keys **{i}** and **{j}** both broken."
        )
    elif cur is not None:
        st.info(f"Comparing key **{cur['i']}** vs key **{cur['j']}** … no shared prime.")

    # ---- the key grid ----------------------------------------------------- #
    st.subheader("The fleet")
    active = {cur["i"], cur["j"]} if cur else set()
    per_row = 10
    for row_start in range(0, len(farm.keys), per_row):
        cols = st.columns(per_row)
        for off in range(per_row):
            idx = row_start + off
            if idx >= len(farm.keys):
                break
            revealed = idx in reveal_at and reveal_at[idx] < step
            color = BROKEN_COLOR if revealed else LOCKED_COLOR
            border = "3px solid #ffd60a" if idx in active else "1px solid #555"
            label = "🔓" if revealed else "🔒"
            tag = (f"<br><span style='font-size:9px;opacity:.85;'>group {key_group[idx]}</span>"
                   if revealed and idx in key_group else "")
            cols[off].markdown(
                f"<div style='background:{color};border:{border};border-radius:8px;"
                f"padding:6px;text-align:center;font-size:11px;color:#fff;'>"
                f"<b>#{idx}</b><br>{label}<br>"
                f"<span style='font-family:monospace;font-size:9px;'>{fingerprint(farm.keys[idx].n)}</span>"
                f"{tag}"
                f"</div>",
                unsafe_allow_html=True,
            )

    # ---- full recovery of one broken key ---------------------------------- #
    if broken:
        st.subheader("Full key recovery")
        broken_idxs = [idx for idx in reveal_at if reveal_at[idx] < step]
        pick = st.selectbox("Recovered key", broken_idxs, format_func=lambda i: f"Key #{i}")
        key = farm.keys[pick]
        rec = batch_gcd.recover_key(key.n, found[pick], key.e)
        ok = rec["d"] == key.d
        a, b = st.columns(2)
        a.markdown(
            f"**Public (what the attacker had)**\n\n"
            f"- N = `{fingerprint(key.n)}`\n- e = `{key.e}`"
        )
        b.markdown(
            f"**Recovered (secret)**\n\n"
            f"- p = `{fingerprint(rec['p'])}`\n- q = `{fingerprint(rec['q'])}`\n"
            f"- d = `{fingerprint(rec['d'])}`"
        )
        st.success("✅ Recovered private key matches the real one." if ok
                   else "❌ mismatch (bug)")

    # ---- the fix ---------------------------------------------------------- #
    with st.expander("🛡️  The fix — properly seed the RNG"):
        st.write(
            "A properly seeded RNG draws **both** primes freshly from the full "
            "~10⁷⁴ possibilities, so every prime across the fleet is unique, no two "
            "moduli share a factor, and every GCD is 1. A truly random fleet:"
        )
        fix_broken, fix_n = st.session_state.get("bg_fix", (0, 0))
        st.metric("Keys broken with the fix", f"{fix_broken} / {fix_n}")

    # ---- drive the animation --------------------------------------------- #
    if st.session_state.bg_playing and step < total:
        st.session_state.bg_step = _advance_to_next_collision(frames, step)
        time.sleep(1.0 / speed)
        st.rerun()
    elif step >= total:
        st.session_state.bg_playing = False


def _advance_to_next_collision(frames: list[dict], step: int, max_scan: int = 60) -> int:
    """Advance to the next collision frame, or by max_scan pairs, whichever first."""
    total = len(frames)
    end = min(step + max_scan, total)
    for k in range(step, end):
        if frames[k]["collision"]:
            return k + 1
    return end


# ========================================================================== #
#  Shared transport controls for the single-key pages
# ========================================================================== #
def _run_controls(prefix: str, total: int, step_amt: int = 1) -> int:
    c1, c2, c3, c4 = st.columns([1, 1, 1, 3])
    if c1.button("▶ Play", key=prefix + "play", use_container_width=True):
        st.session_state[prefix + "playing"] = True
    if c2.button("⏭ Step", key=prefix + "stepbtn", use_container_width=True):
        st.session_state[prefix + "playing"] = False
        st.session_state[prefix + "step"] = min(st.session_state[prefix + "step"] + step_amt, total)
    if c3.button("⏮ Reset", key=prefix + "reset", use_container_width=True):
        st.session_state[prefix + "playing"] = False
        st.session_state[prefix + "step"] = 0
    if c4.button("⏩ Run to end", key=prefix + "end", use_container_width=True):
        st.session_state[prefix + "playing"] = False
        st.session_state[prefix + "step"] = total
    return st.session_state[prefix + "step"]


def _drive(prefix: str, step: int, total: int, speed: int, stride: int = 1) -> None:
    if st.session_state.get(prefix + "playing") and step < total:
        st.session_state[prefix + "step"] = min(step + stride, total)
        time.sleep(1.0 / speed)
        st.rerun()
    elif step >= total:
        st.session_state[prefix + "playing"] = False


# ========================================================================== #
#  Attack page: Fermat factorisation
# ========================================================================== #
def page_fermat() -> None:
    st.title("📐 Fermat factorisation — close primes")
    st.caption(
        "When p and q are generated too close together, N = p·q sits just below a "
        "perfect square. A search upward from ⌈√N⌉ then factors it in a few steps."
    )
    with st.sidebar:
        st.header("Key settings")
        bits = st.selectbox("Key size (bits)", [128, 256, 512, 1024, 2048], index=1, key="fr_bits")
        half = bits // 2
        difficulty = st.slider("Search length (log₂ steps) — bigger = longer, more dramatic",
                               0, 16, 11, key="fr_diff",
                               help="Controls how close p and q are. The search takes ~2^this steps "
                                    "and works at any key size, 2048 included.")
        # gap chosen so Fermat takes ~2**difficulty steps:  steps ≈ 2^(2·gap − half − 3)
        gap = min((difficulty + half + 3) // 2, half - 2)
        seed = st.number_input("Seed", value=1, step=1, key="fr_seed")
        gen = st.button("🔑 Generate key", type="primary", use_container_width=True, key="fr_gen")
        st.divider()
        speed = st.slider("Animation speed", 1, 20, 12, key="fr_speed")

    if gen or "fr_frames" not in st.session_state:
        with st.spinner(f"Generating a {bits}-bit key…"):
            key = keygen.close_primes_key(bits=bits, gap_bits=gap, seed=int(seed))
            frames = []
            for fr in fermat.iter_steps(key.n, max_steps=300_000):
                frames.append(fr)
                if fr["found"] or len(frames) >= 30_000:
                    break
            safe = keygen.safe_key(bits=bits)
            st.session_state.fr_fix_resisted = fermat.attack(safe.public(), max_steps=3000) is None
        st.session_state.fr_key = key
        st.session_state.fr_frames = frames
        st.session_state.fr_shared_bits = half - gap
        st.session_state.fr_step = 0
        st.session_state.fr_playing = False

    key = st.session_state.fr_key
    frames = st.session_state.fr_frames
    total = len(frames)
    found_frame = frames[-1] if frames and frames[-1]["found"] else None
    stride = max(1, total // 60)

    step = _run_controls("fr_", total, step_amt=stride)
    cur = frames[step - 1] if 0 < step <= total else None
    broke = cur is not None and cur["found"]

    m1, m2, m3 = st.columns(3)
    m1.metric("Steps searched", f"{(cur['steps'] if cur else 0):,} / {total:,}")
    m2.metric("Status", "BROKEN 🔓" if broke else "searching…")
    m3.metric("Prime gap", f"2^{gap}")
    st.progress(step / total if total else 0.0)

    shared = st.session_state.get("fr_shared_bits", 0)
    st.markdown(f"**N** = `{fingerprint(key.n)}`  ({key.n.bit_length()} bits) — "
                f"p and q agree in their top ~{shared} of {bits // 2} bits, so √N is close.")
    if cur is not None:
        st.markdown(
            f"Testing **a** = `{fingerprint(cur['a'])}` — is `a² − N` a perfect square?  "
            + ("✅ **yes — factored!**" if cur["is_square"] else "❌ no, keep climbing")
        )

    if found_frame and step >= total:
        p, q = found_frame["p"], found_frame["q"]
        d = modinv(key.e, (p - 1) * (q - 1))
        ok = {p, q} == {key.p, key.q}
        st.subheader("Recovered key")
        a, b = st.columns(2)
        a.markdown(f"**Public**\n\n- N = `{fingerprint(key.n)}`\n- e = `{key.e}`")
        b.markdown(f"**Recovered (secret)**\n\n- p = `{fingerprint(p)}`\n- q = `{fingerprint(q)}`\n- d = `{fingerprint(d)}`")
        st.success("✅ Factored — recovered key matches the real one." if ok else "❌ mismatch (bug)")
    elif step >= total:
        st.warning("Not factored within the step budget — the primes weren't close enough. "
                   "Lower the search length and regenerate.")

    with st.expander("🛡️  The fix — draw p and q independently"):
        st.write(
            "With independently chosen primes, |p − q| is about 2^(bits/2) — "
            "astronomically large — so `a` starts astronomically far from (p+q)/2 "
            "and the search never finishes."
        )
        resisted = st.session_state.get("fr_fix_resisted", True)
        st.metric("Factored within 3000 steps", "no ✅ (resisted)" if resisted else "yes ❌")

    _drive("fr_", step, total, speed, stride=stride)


# ========================================================================== #
#  Attack page: Wiener
# ========================================================================== #
def page_wiener() -> None:
    st.title("🔑 Wiener's attack — tiny private exponent")
    st.caption(
        "A small private exponent d (d < N^0.25) leaks through the "
        "continued-fraction convergents of e/N — no factoring search needed."
    )
    with st.sidebar:
        st.header("Key settings")
        bits = st.selectbox("Key size (bits)", [256, 512, 1024, 2048], index=1, key="wn_bits")
        bound = bits // 4
        d_bits = st.slider("Size of private exponent d (bits)",
                           bound - 40, bound + 16, bound - 8, key="wn_dbits",
                           help=f"N^0.25 ≈ 2^{bound}. Below it → Wiener works; above → safe.")
        seed = st.number_input("Seed", value=1, step=1, key="wn_seed")
        gen = st.button("🔑 Generate key", type="primary", use_container_width=True, key="wn_gen")
        st.divider()
        speed = st.slider("Animation speed", 1, 20, 6, key="wn_speed")

    bound = bits // 4
    if gen or "wn_frames" not in st.session_state:
        with st.spinner(f"Generating a {bits}-bit key…"):
            key = keygen.small_d_key(bits=bits, d_bits=int(d_bits), seed=int(seed))
            frames = list(wiener.iter_steps(key.public()))
            safe = keygen.safe_key(bits=bits)
            st.session_state.wn_fix_fails = wiener.attack(safe.public()) is None
        st.session_state.wn_key = key
        st.session_state.wn_frames = frames
        st.session_state.wn_gen_dbits = int(d_bits)
        st.session_state.wn_gen_bits = bits
        st.session_state.wn_step = 0
        st.session_state.wn_playing = False

    key = st.session_state.wn_key
    frames = st.session_state.wn_frames
    total = len(frames)
    dbits = st.session_state.wn_gen_dbits
    # cliff must match the key that was actually generated, not the live dropdown
    bound = st.session_state.get("wn_gen_bits", bits) // 4
    found_frame = frames[-1] if frames and frames[-1]["found"] else None
    vulnerable = dbits < bound

    step = _run_controls("wn_", total)
    cur = frames[step - 1] if 0 < step <= total else None

    m1, m2, m3 = st.columns(3)
    m1.metric("Convergents tested", f"{step} / {total}")
    m2.metric("d size", f"{dbits} bits")
    m3.metric("N^0.25 cliff", f"{bound} bits", delta=f"{dbits - bound:+d} vs cliff",
              delta_color="inverse")
    st.progress(step / total if total else 0.0)
    st.caption("🟢 d is **below** the N^0.25 cliff — Wiener should succeed."
               if vulnerable else
               "🔴 d is **above** the cliff — Wiener should fail (the safe zone).")

    if cur is not None:
        msg = (f"Convergent #{cur['idx']}:  k = `{cur['k']}`,  d = `{fingerprint(cur['d'])}`  —  "
               + ("φ(N) comes out an integer ✅  " if cur["phi_integer"]
                  else "φ(N) not an integer ❌  ")
               + ("**→ factors N! 🔓**" if cur["found"] else ""))
        st.markdown(msg)

    if found_frame and step >= total:
        p, q, d = found_frame["p"], found_frame["q"], found_frame["d"]
        ok = d == key.d and {p, q} == {key.p, key.q}
        st.subheader("Recovered key")
        a, b = st.columns(2)
        a.markdown(f"**Public**\n\n- N = `{fingerprint(key.n)}`\n- e = `{fingerprint(key.e)}`")
        b.markdown(f"**Recovered (secret)**\n\n- d = `{fingerprint(d)}`\n- p = `{fingerprint(p)}`\n- q = `{fingerprint(q)}`")
        st.success("✅ Recovered d matches the real private key." if ok else "❌ mismatch (bug)")
    elif step >= total:
        st.warning("No convergent factored N — d was too large for Wiener. That's the safe case.")

    with st.expander("🛡️  The fix — pick e first, derive d"):
        st.write(
            "A proper key fixes e = 65537 and derives d, so d is about as large as N. "
            "None of the convergents of e/N reveal it."
        )
        st.metric("Wiener on a proper key",
                  "fails ✅" if st.session_state.get("wn_fix_fails", True) else "breaks ❌")

    _drive("wn_", step, total, speed)


# ========================================================================== #
#  Attack page: Håstad broadcast
# ========================================================================== #
def page_hastad() -> None:
    st.title("📡 Håstad broadcast — e = 3, no padding")
    st.caption(
        "Send the same unpadded message to ≥ 3 people with e = 3: combining the "
        "ciphertexts by CRT and taking a cube root recovers it, with no factoring."
    )
    with st.sidebar:
        st.header("Broadcast settings")
        bits = st.selectbox("Key size (bits)", [256, 512, 1024, 2048], index=1, key="hs_bits")
        recipients = st.slider("Number of recipients", 2, 6, 3, key="hs_rcpt",
                              help="The attack needs at least e = 3.")
        message = st.text_input("Secret message", "crypto", key="hs_msg")
        seed = st.number_input("Seed", value=1, step=1, key="hs_seed")
        gen = st.button("📣 Broadcast", type="primary", use_container_width=True, key="hs_gen")
        st.divider()
        speed = st.slider("Animation speed", 1, 20, 3, key="hs_speed")

    e = 3
    if gen or "hs_frames" not in st.session_state:
      with st.spinner(f"Generating {recipients} keys at {bits}-bit…"):
        keys = [keygen.small_e_key(bits=bits, e=e, seed=int(seed) * 100 + i)
                for i in range(recipients)]
        raw = message.encode("utf-8") or b"\x00"
        m_int = int.from_bytes(raw, "big")
        min_n = min(k.n for k in keys)
        if m_int >= min_n:
            m_int %= min_n
        cts = [k.encrypt(m_int) for k in keys]
        mods = [k.n for k in keys]
        st.session_state.hs_keys = keys
        st.session_state.hs_frames = list(hastad.iter_steps(cts, mods, e))
        st.session_state.hs_step = 0
        st.session_state.hs_playing = False

    keys = st.session_state.hs_keys
    frames = st.session_state.hs_frames
    total = len(frames)
    final = frames[-1] if frames else None

    step = _run_controls("hs_", total)
    cur = frames[step - 1] if 0 < step <= total else None
    recovered = bool(final and final.get("message") is not None and step >= total)

    m1, m2 = st.columns(2)
    m1.metric("Ciphertexts combined", f"{min(step, len(keys))} / {len(keys)}")
    m2.metric("Status", "RECOVERED 🔓" if recovered else "combining…")
    st.progress(step / total if total else 0.0)

    # recipient cards
    if cur is not None and cur.get("stage") == "combine":
        revealed = cur["added"] + 1
    elif step >= total:
        revealed = len(keys)
    else:
        revealed = 0
    st.subheader("Recipients (same message, e = 3)")
    cols = st.columns(len(keys))
    for i, k in enumerate(keys):
        lit = i < revealed
        color = "#2e7d32" if lit else "#2b2b2b"
        cols[i].markdown(
            f"<div style='background:{color};border:1px solid #555;border-radius:8px;"
            f"padding:8px;text-align:center;font-size:12px;color:#fff;'>"
            f"<b>#{i}</b><br>{'📨' if lit else '🔒'}<br>"
            f"<span style='font-family:monospace;font-size:9px;'>N={fingerprint(k.n)}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    if cur is not None and cur.get("stage") == "combine":
        st.markdown(
            f"Folded in ciphertext #{cur['added']} → combined value `{fingerprint(cur['combined'])}`"
            + ("" if cur["enough"] else "  *(need ≥ 3 before the cube root works)*")
        )
    elif cur is not None and cur.get("stage") == "root":
        st.markdown("Took the **integer cube root** of the CRT-combined value.")

    if step >= total:
        if final and final.get("message") is not None:
            m = final["message"]
            try:
                txt = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8", "replace")
            except Exception:
                txt = str(m)
            st.success(f"✅ Recovered message:  **{txt}**")
            st.caption("Recovered from ciphertexts alone — no key was factored.")
        else:
            st.error("❌ Cube root not exact — fewer than 3 ciphertexts. Håstad needs e = 3 of them. "
                     "Raise the recipient count to 3+.")

    with st.expander("🛡️  The fix — pad the message (OAEP)"):
        st.write(
            "Randomised OAEP padding makes each recipient's plaintext different, so the "
            "ciphertexts are no longer encryptions of the *same* integer — CRT has nothing "
            "to line up, and the cube root is meaningless."
        )

    _drive("hs_", step, total, speed)


# ========================================================================== #
#  Navigation
# ========================================================================== #
PAGES = {
    "Batch GCD (low-entropy RNG)": page_batch_gcd,
    "Fermat (close primes)": page_fermat,
    "Wiener (small d)": page_wiener,
    "Håstad (e=3 broadcast)": page_hastad,
}

st.sidebar.title("Weak RSA 🔓")
st.sidebar.caption("Pick a weakness, then watch the attack.")
choice = st.sidebar.radio("Attack", list(PAGES), label_visibility="collapsed")
st.sidebar.divider()
PAGES[choice]()
