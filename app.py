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
from weakrsa.attacks import batch_gcd

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
        bits = st.selectbox("Key size (bits)", [256, 512, 1024], index=1,
                            help="Attack is size-independent; smaller keeps the demo snappy.")
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
            "moduli share a factor, and every GCD is 1. Same fleet size, real randomness:"
        )
        safe_keys = [keygen.safe_key(bits=bits) for _ in range(count)]
        safe_mods = [k.n for k in safe_keys]
        safe_found = batch_gcd.batch_gcd(safe_mods)
        st.metric("Keys broken with the fix", f"{len(safe_found)} / {len(safe_keys)}")

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
#  Stub pages for the other three attacks (skeleton to expand into)
# ========================================================================== #
def _stub(title: str, caption: str, plan: str) -> None:
    st.title(title)
    st.caption(caption)
    st.info("🚧 Interactive page coming next — planned layout below.")
    st.markdown(plan)


def page_fermat() -> None:
    _stub(
        "📐 Fermat factorisation — close primes",
        "When p and q are generated too close together, N sits just below a "
        "perfect square and factors in a short search.",
        "- **Slider:** prime gap.\n"
        "- **Animation:** `a` climbs from ⌈√N⌉; each step shows `a²−N` and "
        "whether it is a perfect square; green flash + factor reveal on success.\n"
        "- **Live:** step counter vs. the `(p−q)²/(4√N)` estimate.\n"
        "- **Fix toggle:** independently-drawn primes → search never terminates.",
    )


def page_wiener() -> None:
    _stub(
        "🔑 Wiener's attack — tiny private exponent",
        "A small private exponent d (d < N^0.25) leaks through the continued "
        "fraction of e/N.",
        "- **Slider:** size of d (bits).\n"
        "- **Animation:** convergents of e/N tested one by one; each shows k/d, "
        "the candidate φ, and whether it factors N.\n"
        "- **Gauge:** where d sits relative to the N^0.25 cliff.\n"
        "- **Fix toggle:** choose e first (65537), derive d → attack fails.",
    )


def page_hastad() -> None:
    _stub(
        "📡 Håstad broadcast — e = 3, no padding",
        "The same message sent to 3 recipients with e = 3 and no padding is "
        "recoverable by CRT + a cube root, without factoring anything.",
        "- **Input:** type a message; 3 recipients encrypt it.\n"
        "- **Animation:** CRT combines the 3 ciphertexts → integer cube root → "
        "message appears.\n"
        "- **Toggle:** drop to 2 ciphertexts and watch it fail.\n"
        "- **Fix toggle:** OAEP padding → broadcast attack fails.",
    )


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
