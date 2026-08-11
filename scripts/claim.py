#!/usr/bin/env python3
"""Ticket claim mutex for concurrent agent lanes (any team: ZTR, ZPAY, ...).

    python3 scripts/claim.py check   ZTR-30 [--run <uuid>]            # exit 0 = takeable, 1 = held
    python3 scripts/claim.py claim   ZTR-30 implementer "" In-Work [--run <uuid>]
    python3 scripts/claim.py beat    ZTR-30 implementer "wrote the fixture emitter" --run <uuid>
    python3 scripts/claim.py release ZPAY-216 implementer "PR #1270 opened" QA-Review --run <uuid>
    python3 scripts/claim.py release ZTR-30 implementer "blocked, handing back" --run <uuid>  # -> Ready
    python3 scripts/claim.py windows ZPAY-216                          # claim windows as JSON
    python3 scripts/claim.py selftest                                  # offline routing check

The team and the workflow state are resolved from the identifier the caller typed,
never from a pinned UUID — the same rule scripts/linear.py states and for the same
reason. A hardcoded team id silently routes every ZPAY-<n> call at ZTR-<n> (ZPAY-216:
every claim, beat and release landed on another team's ticket, and the strict-dual
fence died CLAIM_WINDOWS_UNAVAILABLE on every ZPAY PR). `selftest` fails if a pinned
UUID ever comes back.

A claim is a comment containing a CLAIM marker. It stays valid only while the claimant
keeps commenting: if the newest comment from that claimant is older than STALE_MINUTES,
the claim is dead and any lane may take the ticket.

Lane identity is lane=<role> plus run=<uuid>, minted at claim time (or supplied with
--run, e.g. an orchestrator dispatch identity) and echoed by every beat/release. Every
fleet uses the same role names, so the role alone cannot distinguish lanes: claim
refuses a live claim held by a different run even at the same role, check prints the
holder's run so a lane can tell its own claim from a rival's, and release refuses to
dissolve a claim whose run the caller does not hold. If two lanes claim within
seconds, the earliest claim holds; the later lane's check shows a foreign run and it
stands down.

Dual-review exception: the sub-lanes reviewer-A and reviewer-B may BOTH hold
one ticket at once (co-hold). Every other role stays single-holder. A third reviewer, a
second holder of the same reviewer letter, or any non-reviewer second holder is refused.

Backwards compatibility with pre-run copies of this script (other fleets may run them
concurrently): markers keep lane= first so old copies still regex-parse them, and
run-less (legacy) markers keep their old meaning here — a live legacy claim from a
different lane name blocks a claim, a legacy RELEASE dissolves the current holder, and
a same-lane legacy claim keeps accepting run-less beats until it is re-claimed (which
upgrades it to a run). Note a legacy RELEASE from an old copy can still dissolve a
run-scoped claim until every fleet upgrades; the run= protection applies to markers
written by this version.

check exits 0 when the ticket is takeable, 1 when a live claim exists (the printed run
tells you whether it is yours). All timestamps are UTC — Linear returns UTC and
comparing against local time reads a claim as an hour stale (or an hour fresh)
depending on the season.
"""
import json, os, re, sys, urllib.request, uuid
from datetime import datetime, timedelta, timezone

STALE_MINUTES = 60
# ZUP (the original zucoins-merchant-wallets team) is retired — refuse it rather than
# operating on its stale tickets. Every other team key routes by the identifier itself.
RETIRED_TEAMS = {"ZUP"}
# Accepted `claim`/`release` state arguments. The UUID behind each name is resolved on
# the identifier's OWN board at call time; this set only bounds what a lane may ask for,
# so a typo cannot silently land a ticket somewhere nobody looks. Mergers close tickets
# themselves, so Done must be reachable or a merger's release drags a finished ticket
# backwards; Triage/Canceled/Duplicate are the sweeper's terminal dispositions.
CANONICAL_STATES = {
    "Ready", "In Work", "QA Review", "Backlog", "Done",
    "Triage", "Canceled", "Duplicate",
}
# Callers (and every agent doc) spell the states hyphenated; ZTR also renamed its states
# and the pre-migration names are still in circulation.
STATE_ALIASES = {
    "Todo": "Ready",
    "In Progress": "In Work",
    "In-Work": "In Work",
    "In Review": "QA Review",
    "QA-Review": "QA Review",
    "Verifying": "QA Review",
}
MARK = "\U0001F512 CLAIM"
REL = "\U0001F513 RELEASE"


def token():
    p = os.path.join(os.path.dirname(__file__), "..", ".secrets.env")
    for line in open(p):
        if line.startswith("linear="):
            return line.split("=", 1)[1].strip()
    sys.exit("no linear token in .secrets.env")


def gql(q, v=None):
    r = urllib.request.Request(
        "https://api.linear.app/graphql",
        data=json.dumps({"query": q, "variables": v or {}}).encode(),
        headers={"Authorization": token(), "Content-Type": "application/json"},
    )
    d = json.loads(urllib.request.urlopen(r).read())
    if d.get("errors"):
        sys.exit(f"linear error: {json.dumps(d['errors'])[:300]}")
    return d["data"]


def parse_identifier(ident):
    """Split `ZPAY-216` into its team key and number, rejecting anything ambiguous."""
    m = re.fullmatch(r"([A-Za-z]+)-(\d+)", (ident or "").strip())
    if not m:
        sys.exit(f"bad issue identifier {ident!r} — expected a full id like ZTR-30 or ZPAY-216")
    key = m.group(1).upper()
    if key in RETIRED_TEAMS:
        sys.exit(f"team {key} is retired — use the current team's identifier for this work")
    return key, int(m.group(2))


def state_uuid(team_key, name):
    """Resolve a workflow state name on `team_key`'s OWN board, honouring the aliases."""
    want = STATE_ALIASES.get(name, name)
    d = gql(
        """query($k:String!,$n:String!){
             workflowStates(filter:{team:{key:{eq:$k}}, name:{eq:$n}}){ nodes{ id name } } }""",
        {"k": team_key, "n": want},
    )
    ns = d["workflowStates"]["nodes"]
    if not ns:
        sys.exit(f"no workflow state named {want!r} on team {team_key}")
    return ns[0]["id"], ns[0]["name"]


def check_state_arg(target):
    """Reject a state name no board uses before any mutation goes out."""
    if STATE_ALIASES.get(target, target) not in CANONICAL_STATES:
        sys.exit(f"unknown state {target}; use one of {', '.join(sorted(CANONICAL_STATES))}")


def issue(ident):
    key, n = parse_identifier(ident)
    d = gql(
        """query($k:String!,$n:Float){ issues(filter:{team:{key:{eq:$k}}, number:{eq:$n}}){ nodes{
             id identifier state{name}
             comments(first:60){ nodes{ body createdAt } } } } }""",
        {"k": key, "n": n},
    )
    ns = d["issues"]["nodes"]
    if not ns:
        sys.exit(f"{ident} not found")
    if ns[0]["identifier"].upper() != f"{key}-{n}":
        sys.exit(f"resolved {ns[0]['identifier']} for {ident} — wrong team, refusing")
    return ns[0]


def parse_ts(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def marker(body):
    """(kind, lane, run) for a CLAIM/RELEASE marker, else None. kind: claim|release.

    Only the first line is parsed: note text may legitimately quote run=<uuid>
    strings (dispatch identities, evidence) and must never be read as identity.
    run is None for legacy (pre-run) markers.
    """
    first = body.split("\n", 1)[0]
    kind = "claim" if MARK in first else "release" if REL in first else None
    if not kind:
        return None
    m = re.search(r"lane=(\S+)", first)
    r = re.search(r"run=(\S+)", first)
    return kind, (m.group(1) if m else "unknown"), (r.group(1) if r else None)


def identity_hit(body, lane, run):
    """Whether a comment refreshes the (lane, run) identity. A run identity refreshes
    only on a FIRST-LINE run=<uuid> — note text may quote runs (takeover notes,
    dispatch identities) and must never keep a claim alive. A legacy identity
    refreshes on any comment carrying lane=<lane> — the old script's semantics."""
    if run:
        return f"run={run}" in body.split("\n", 1)[0]
    return f"lane={lane}" in body


def idle_min(nodes, lane, run, ref, start=0):
    """Minutes between ref and the newest refreshing comment in nodes[start:]
    (newest-first; start>0 excludes that many newer comments). inf when nothing
    from this identity is in the window."""
    for c in nodes[start:]:
        if identity_hit(c["body"], lane, run):
            return (ref - parse_ts(c["createdAt"])).total_seconds() / 60.0
    return float("inf")


# Dual-review sub-lanes that may co-hold one ticket. Every other role
# remains single-holder. Cap is inherent: only these two names are eligible.
COHOLD_LANES = frozenset({"reviewer-A", "reviewer-B"})


def _cohold_lane(lane):
    return lane in COHOLD_LANES


def _id_key(lane, run):
    """Stable identity key for a claim: run uuid, or legacy:<lane> when run-less."""
    return run if run is not None else f"legacy:{lane}"


def _can_cohold_join(lane, live_hs):
    """True when `lane` may join the current live holders as a dual-review co-holder."""
    if not _cohold_lane(lane):
        return False
    if not live_hs:
        return True
    if not all(_cohold_lane(h["lane"]) for h in live_hs):
        return False
    if lane in {h["lane"] for h in live_hs}:
        return False  # same letter already held (different run = race loser)
    return len(live_hs) < len(COHOLD_LANES)


def holders(it):
    """Current holders [{lane, run, idle_min, at}, ...], oldest first; empty if none.

    Replays markers oldest-first. Default is single-holder (earliest live claim wins;
    a later different identity takes over only if every current holder was already
    stale AT THAT MOMENT — judged from comments OLDER than the new marker, so a
    marker never counts toward its own takeover). Dual-review exception: reviewer-A and
    reviewer-B may co-hold. A claim by a holder's own identity refreshes; a run-bearing
    claim upgrades a run-less legacy claim of the same lane name in place. A RELEASE
    cancels only its own run; a run-less (legacy) RELEASE cancels every holder.
    """
    nodes = it["comments"]["nodes"]   # newest first
    hs = {}  # id_key -> {lane, run, at}
    for idx in range(len(nodes) - 1, -1, -1):   # oldest -> newest
        c = nodes[idx]
        m = marker(c["body"])
        if not m:
            continue
        kind, lane, run = m
        if kind == "release":
            if run is None:
                hs.clear()
            else:
                hs = {k: v for k, v in hs.items() if v["run"] != run}
            continue
        k = _id_key(lane, run)
        if k in hs:
            hs[k]["at"] = c["createdAt"]                   # same identity refreshing
            continue
        leg = f"legacy:{lane}"
        if run and leg in hs:
            del hs[leg]
            hs[k] = {"lane": lane, "run": run, "at": c["createdAt"]}  # legacy -> run
            continue
        ts = parse_ts(c["createdAt"])
        live = {kk: v for kk, v in hs.items()
                if idle_min(nodes, v["lane"], v["run"], ts, start=idx + 1) <= STALE_MINUTES}
        if not live:
            # empty, or every holder already stale at this moment -> exclusive takeover
            hs = {k: {"lane": lane, "run": run, "at": c["createdAt"]}}
            continue
        if _can_cohold_join(lane, list(live.values())):
            hs = dict(live)                                # drop any stale siblings
            hs[k] = {"lane": lane, "run": run, "at": c["createdAt"]}
            continue
        # else: race loser / non-cohold second holder — inert while live holders remain
    if not hs:
        return []
    now = datetime.now(timezone.utc)
    out = [{**h, "idle_min": idle_min(nodes, h["lane"], h["run"], now)}
           for h in hs.values()]
    out.sort(key=lambda h: h["at"])
    return out


def holder(it):
    """Back-compat single view: earliest live holder, else earliest (possibly stale), else None.

    Prefer holders() when co-hold matters — dual review can return two live entries.
    """
    hs = holders(it)
    if not hs:
        return None
    live = [h for h in hs if h["idle_min"] <= STALE_MINUTES]
    return (live or hs)[0]


def _stale_end(nodes, lane, run, start=0):
    """The timestamp a never-released claim stopped vouching: its last refreshing
    comment in nodes[start:] plus STALE_MINUTES — the moment check/claim call it dead.
    start>0 bounds it to comments older than a takeover, so a zombie beat posted after
    the takeover (inert per holder()) cannot stretch the dead lane's window."""
    last = next(c["createdAt"] for c in nodes[start:] if identity_hit(c["body"], lane, run))
    return f"{parse_ts(last) + timedelta(minutes=STALE_MINUTES):%Y-%m-%dT%H:%M:%S.%f}"[:-3] + "Z"


def windows(it):
    """[{lane, run, start, end}] — every claim window on the ticket, oldest first.

    ONE live window per LANE NAME at a time (F2). start is a lane's first CLAIM
    marker; end is the RELEASE that dissolved it, or — for a claim nobody released —
    its last refreshing comment plus STALE_MINUTES, the moment check/claim call the
    claim dead. Left open, an abandoned claim would vouch for verdicts forever, the
    standing credential a forger wants; end is null only while the claim is live now.
    Beats and same-run re-claims extend the open window; a claim after that identity's
    release opens a genuinely new one.

    Earliest-wins, the same rule holder() enforces: while a lane's window is LIVE, a
    claim by a DIFFERENT run on the SAME lane name is a race-loser (or a forged
    duplicate) and opens NO window. The pre-F2 code keyed windows by run and minted
    one per CLAIM regardless, so "held the claim" cost one Linear comment on the
    shared token — mint a window, post two head-pinned PASSes under it, clear STRICT
    dual alone. A different run takes over only when the open holder was already stale
    AT THAT MOMENT (judged from markers OLDER than the new one, so a marker never
    counts toward its own takeover). DISTINCT lane names (reviewer-A vs reviewer-B)
    each keep their own window, so an honest dual review with two reviewer sub-lanes
    coexists. A run-less legacy RELEASE closes every open window, matching holder();
    a legacy claim upgrades to a run in place when the same lane re-claims with one.

    Consumers (release-targets-verdict-evidence.mjs) use these to prove a review
    verdict was posted by the lane whose run id its header claims — the PR #1794
    run-identity impersonation. Windows are the honest bound available: they say a
    run held the ticket at that moment, not that this GitHub comment came from that
    process. Every agent posts under one shared GitHub account, so posting time
    inside the window is the strongest provenance the trail carries.

    ponytail: bounded by issue()'s comments(first:60) — on a ticket with more than
    60 comments the oldest CLAIM scrolls out of the window list and its verdicts
    read as unproven (fail closed, refuse merge). Paginate here if that starts
    biting real merges.
    """
    nodes = it["comments"]["nodes"]
    out, open_by = [], {}                              # open_by: lane name -> its open window
    for idx in range(len(nodes) - 1, -1, -1):          # oldest -> newest
        c = nodes[idx]
        m = marker(c["body"])
        if not m:
            continue
        kind, lane, run = m
        if kind == "release":
            if run is None:                            # legacy release closes everything
                for w in open_by.values():
                    w["end"] = c["createdAt"]
                open_by.clear()
            else:
                w = open_by.get(lane)
                if w and w["run"] == run:              # only its own run's release closes it
                    w["end"] = c["createdAt"]
                    del open_by[lane]
            continue
        w = open_by.get(lane)
        if w is None:                                  # lane free -> open a window
            w = {"lane": lane, "run": run, "start": c["createdAt"], "end": None}
            open_by[lane] = w
            out.append(w)
        elif (w["run"] or f"legacy:{lane}") == (run or f"legacy:{lane}"):
            pass                                       # same identity refreshing -> extend
        elif w["run"] is None and run:
            w["run"] = run                             # legacy -> run upgrade in place
        elif idle_min(nodes, w["lane"], w["run"], parse_ts(c["createdAt"]),
                      start=idx + 1) > STALE_MINUTES:  # stale holder -> take over
            w["end"] = _stale_end(nodes, w["lane"], w["run"], start=idx + 1)
            nw = {"lane": lane, "run": run, "start": c["createdAt"], "end": None}
            open_by[lane] = nw
            out.append(nw)
        # else: race-loser claim while the same lane is live -> NO window (F2)

    now = datetime.now(timezone.utc)
    for w in out:
        if w["end"] is None and idle_min(nodes, w["lane"], w["run"], now) > STALE_MINUTES:
            w["end"] = _stale_end(nodes, w["lane"], w["run"])
    return out


def run_desc(h):
    return f" run={h['run']}" if h["run"] else " (run-less legacy claim)"


def split_run(argv):
    """Pull --run <uuid> | --run=<uuid> out of argv; positionals keep their old shape."""
    run, rest, i = None, [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--run" and i + 1 < len(argv):
            run, i = argv[i + 1], i + 2
        elif a.startswith("--run="):
            run, i = a.split("=", 1)[1], i + 1
        else:
            rest.append(a)
            i += 1
    if run and re.search(r"\s", run):
        sys.exit(f"run must be a single token (a uuid), got {run!r}")
    return run, rest


def _fmt_holders(hs):
    """Human-readable holder list for check/claim messages."""
    return " + ".join(
        f"lane={h['lane']}{run_desc(h)} (idle {h['idle_min']:.0f}m)" for h in hs
    )


def _find_holder(hs, lane, run_arg):
    """Match a holder by run (preferred) or by run-less legacy lane name."""
    if run_arg is not None:
        for h in hs:
            if h["run"] == run_arg:
                return h
        return None
    for h in hs:
        if h["run"] is None and h["lane"] == lane:
            return h
    return None


UUID_SHAPED = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.I)


def _pinned_uuids():
    """Module-level constants that are (or contain) a Linear UUID — the ZPAY-216 defect
    shape. A pinned team/state id keeps routing at the old team forever, and the failure
    is silent: `ZPAY-216` resolves, it just resolves to somebody else's ticket."""
    found = []
    for name, value in globals().items():
        if name.startswith("_") or callable(value):
            continue
        items = value.items() if isinstance(value, dict) else (
            enumerate(value) if isinstance(value, (list, tuple, set, frozenset)) else [(name, value)]
        )
        for key, item in items:
            if isinstance(item, str) and UUID_SHAPED.match(item):
                found.append(f"{name}[{key!r}]" if key != name else name)
            if isinstance(key, str) and UUID_SHAPED.match(key):
                found.append(f"{name} key {key!r}")
    return sorted(found)


def selftest():
    """Offline check of the routing logic — no Linear access, no token needed."""
    assert parse_identifier("ZPAY-216") == ("ZPAY", 216)
    assert parse_identifier("ZTR-30") == ("ZTR", 30)
    assert parse_identifier(" zpay-216 ") == ("ZPAY", 216), "case/space tolerant"
    for bad in ("216", "ZPAY", "ZPAY-", "ZPAY-7x", "ZPAY-216-1", "", None):
        try:
            parse_identifier(bad)
        except SystemExit:
            continue
        raise AssertionError(f"{bad!r} should have been rejected")
    try:
        parse_identifier("ZUP-216")
    except SystemExit:
        pass
    else:
        raise AssertionError("retired ZUP must be refused, not resolved")
    # AC2: the regression guard. Any pinned team/state UUID reintroduces the misroute.
    pinned = _pinned_uuids()
    assert not pinned, ("pinned Linear UUIDs are the ZPAY-216 misroute defect; resolve "
                        f"team and state from the identifier instead: {pinned}")
    # Hyphenated spellings are what every agent doc and dispatch line passes.
    assert STATE_ALIASES["QA-Review"] == "QA Review"
    assert STATE_ALIASES["In-Work"] == "In Work"
    for name in ("Ready", "In-Work", "QA-Review", "Backlog", "Done", "Triage", "Canceled", "Duplicate"):
        check_state_arg(name)  # exits on an unknown state
    for bad in ("Shipped", "in-work", ""):
        try:
            check_state_arg(bad)
        except SystemExit:
            continue
        raise AssertionError(f"state {bad!r} should have been rejected")
    print("selftest ok")


def main():
    if sys.argv[1:2] == ["selftest"]:
        return selftest()
    run_arg, args = split_run(sys.argv[1:])
    if len(args) < 2:
        sys.exit(__doc__)
    cmd, ident = args[0], args[1]
    it = issue(ident)
    hs = holders(it)
    live_hs = [h for h in hs if h["idle_min"] <= STALE_MINUTES]
    h = live_hs[0] if live_hs else (hs[0] if hs else None)  # primary for single-holder msgs

    if cmd == "check":
        if not hs:
            print(f"{ident} FREE (state={it['state']['name']})")
            return
        if not live_hs:
            print(f"{ident} STALE — {_fmt_holders(hs)} > {STALE_MINUTES}m; takeable")
            return
        held = f"{ident} HELD by {_fmt_holders(live_hs)}"
        mine = run_arg and any(x["run"] == run_arg for x in live_hs)
        open_cohold = (
            all(_cohold_lane(x["lane"]) for x in live_hs)
            and len(live_hs) < len(COHOLD_LANES)
            and {x["lane"] for x in live_hs} < COHOLD_LANES
        )
        free_letter = (next(iter(COHOLD_LANES - {x["lane"] for x in live_hs}), None)
                       if open_cohold else None)
        if mine:
            print(f"{held} — this is YOUR claim (run matches)")
        elif run_arg and any(x["run"] is None for x in live_hs):
            leg = next(x for x in live_hs if x["run"] is None)
            print(f"{held} — run-less claim; if lane={leg['lane']} is your lane, "
                  f"re-claim with --run {run_arg} to bind that run to it")
        elif run_arg and open_cohold:
            print(f"{held} — held by a DIFFERENT run (yours: {run_arg}); "
                  f"stand down unless you are claiming co-hold lane={free_letter}")
        elif run_arg:
            print(f"{held} — held by a DIFFERENT run (yours: {run_arg}); stand down")
        elif open_cohold:
            print(f"{held} — co-hold open for lane={free_letter}; other roles must not work it")
        else:
            print(f"{held} — do NOT work it")
        sys.exit(1)

    if cmd == "windows":
        print(json.dumps({"ticket": ident, "windows": windows(it)}))
        return

    if len(args) < 3:
        sys.exit(__doc__)
    lane = args[2]
    note = args[3] if len(args) > 3 else ""

    if cmd == "claim":
        run = run_arg or str(uuid.uuid4())
        # own = this exact run already holds, OR a run-less legacy claim of this lane (upgrade)
        own_h = next((x for x in hs if x["run"] is not None and x["run"] == run), None)
        if own_h is None:
            own_h = next((x for x in hs if x["run"] is None and x["lane"] == lane), None)
        joining = (not own_h) and live_hs and _can_cohold_join(lane, live_hs)
        if live_hs and not own_h and not joining:
            sys.exit(f"REFUSED: {ident} held by {_fmt_holders(live_hs)} "
                     f"— a different run holds a live claim; stand down")
        took = ""
        if joining:
            took = (f"\n\nJoining co-hold with {_fmt_holders(live_hs)} "
                    f"(reviewer-A/B dual-review co-hold, ZTR-1068).")
        elif hs and not own_h and not live_hs:
            took = (f"\n\nTaking over from {_fmt_holders(hs)}, whose claim went silent for "
                    f"> {STALE_MINUTES}m stale threshold.")
        elif own_h and own_h["run"] is None:
            took = f"\n\nUpgrading the run-less legacy claim by lane={lane} to run={run}."
        skip_msg = (
            "Dual-review co-hold: reviewer-A and reviewer-B may both hold; every other role "
            "must skip this ticket while either claim stays live."
            if _cohold_lane(lane) else
            "This lane is working the ticket now — other lanes must skip it while this claim stays live."
        )
        body = (f"{MARK} lane={lane} run={run}\n\nClaimed at {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ} (UTC). "
                f"{skip_msg} "
                f"The claim expires if this lane posts nothing for {STALE_MINUTES} minutes."
                + (f"\n\n{note}" if note else "") + took)
        gql("mutation($i:String!,$b:String!){ commentCreate(input:{issueId:$i,body:$b}){success} }",
            {"i": it["id"], "b": body})
        # Claiming is the mutex, NOT a workflow transition. Pass a 5th arg to also move the
        # ticket: implementer uses In-Work; reviewer/merger claim tickets already sitting in
        # QA Review and must not drag them backwards, so they pass nothing.
        target = args[4] if len(args) > 4 else None
        if target:
            check_state_arg(target)
            gql("mutation($i:String!,$s:String!){ issueUpdate(id:$i,input:{stateId:$s}){success} }",
                {"i": it["id"], "s": state_uuid(parse_identifier(ident)[0], target)[0]})
        print(f"{ident} CLAIMED by lane={lane} run={run}"
              + (f" -> {target}" if target else f" (state unchanged: {it['state']['name']})")
              + (" [co-hold]" if joining else "")
              + "\nUse this run on every beat/release: --run " + run)

    elif cmd == "beat":
        # Beat must name the caller's own holder — under co-hold, matching run picks the right one.
        target_h = _find_holder(hs, lane, run_arg)
        if not target_h and run_arg is None and h and h["run"] is None and h["lane"] == lane:
            target_h = h
        if not target_h:
            if not hs:
                sys.exit(f"REFUSED: {ident} is not held by lane={lane} — re-claim first")
            if run_arg is None and any(x["run"] for x in hs):
                sys.exit(f"REFUSED: {ident} is held by {_fmt_holders(hs)} — "
                         f"re-run with --run (check prints the holder's run)")
            sys.exit(f"REFUSED: {ident} is held by {_fmt_holders(hs)} — "
                     f"your run={run_arg or '(none)'} does not match; stand down")
        if target_h["run"]:
            if not run_arg:
                sys.exit(f"REFUSED: {ident} is held by lane={target_h['lane']} run={target_h['run']} — "
                         f"re-run with --run (check prints the holder's run)")
            if target_h["run"] != run_arg:
                sys.exit(f"REFUSED: {ident} is held by {_fmt_holders(hs)} — "
                         f"your run={run_arg} does not match; stand down")
        elif target_h["lane"] != lane:
            sys.exit(f"REFUSED: {ident} is held by lane={target_h['lane']} "
                     f"(run-less legacy claim) — re-claim first")
        first = (f"{MARK} lane={lane}"
                 + (f" run={target_h['run']}" if target_h["run"] else "")
                 + " · heartbeat")
        gql("mutation($i:String!,$b:String!){ commentCreate(input:{issueId:$i,body:$b}){success} }",
            {"i": it["id"], "b": f"{first}\n\n{note or 'still working'}"})
        print(f"{ident} heartbeat by lane={lane}{run_desc(target_h)}")

    elif cmd == "release":
        # Default Ready: an abandoned ticket must never be left looking mid-flight.
        # Pass a 5th arg (Ready | QA-Review | Backlog | In-Work) to land it elsewhere.
        target = args[4] if len(args) > 4 else "Ready"
        check_state_arg(target)
        target_h = _find_holder(hs, lane, run_arg)
        if live_hs:
            if run_arg and not any(x["run"] == run_arg for x in live_hs):
                if not (target_h and target_h["run"] == run_arg):
                    sys.exit(f"REFUSED: {ident} is held by {_fmt_holders(live_hs)} "
                             f"— your run={run_arg or '(none given)'} does not "
                             f"match a holder's; refusing to dissolve another lane's claim. It goes "
                             f"stale after {STALE_MINUTES}m of silence and can then be taken over with claim.")
            if not run_arg and h and h["run"]:
                sys.exit(f"REFUSED: {ident} is held by {_fmt_holders(live_hs)} "
                         f"— your run=(none given) does not "
                         f"match a holder's; refusing to dissolve another lane's claim. It goes "
                         f"stale after {STALE_MINUTES}m of silence and can then be taken over with claim.")
            if not run_arg and h and not h["run"] and h["lane"] != lane:
                print(f"WARNING: releasing a run-less legacy claim held by lane={h['lane']} — "
                      f"old-script semantics allow this; run-scoped claims refuse it.",
                      file=sys.stderr)
        # The RELEASE marker carries the run of the claim it dissolves — and only then.
        rel_run = (target_h["run"] if (target_h and target_h["run"] and target_h["run"] == run_arg)
                   else None)
        first = f"{REL} lane={lane}" + (f" run={rel_run}" if rel_run else "") + f" -> {target}"
        gql("mutation($i:String!,$b:String!){ commentCreate(input:{issueId:$i,body:$b}){success} }",
            {"i": it["id"], "b": f"{first}\n\n{note or 'released'}"})
        # Under co-hold, dissolving one side must not yank the ticket out from under the
        # remaining holder. Only the last live holder (or a legacy wipe) moves state.
        if rel_run is None:
            remaining = []  # legacy run-less RELEASE clears every holder
        else:
            remaining = [x for x in live_hs if x["run"] != rel_run]
        if remaining:
            print(f"{ident} RELEASED by lane={lane} run={rel_run} "
                  f"(state unchanged: {it['state']['name']}; still held by {_fmt_holders(remaining)})")
        else:
            gql("mutation($i:String!,$s:String!){ issueUpdate(id:$i,input:{stateId:$s}){success} }",
                {"i": it["id"], "s": state_uuid(parse_identifier(ident)[0], target)[0]})
            print(f"{ident} RELEASED by lane={lane}"
                  + (f" run={rel_run}" if rel_run else "")
                  + f" -> {target}")
    else:
        sys.exit(__doc__)

if __name__ == "__main__":
    main()
