#!/usr/bin/env python3
"""Regression tests for scripts/claim.py (run-scoped claim identity).

Run from the repo root:  python3 scripts/claim.test.py        (stdlib only, no Linear access)

Covers the run-identity acceptance criteria:
  - a same-role claim with a different run is refused while the holder is live;
  - a race loser's release (command or stray marker) cannot dissolve the winner's claim;
  - check prints the holder's run and distinguishes self from rival;
plus the backwards-compatibility contract for run-less (legacy) markers and the
documented stale-takeover / earliest-claim-wins semantics.

Dual-review co-hold: reviewer-A and reviewer-B may both hold one ticket; a third
reviewer or a non-reviewer second holder is refused; implementer/merger single-holder
mutex is unchanged; two co-hold windows remain independent for the fence.
"""
import io, os, re, sys, unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.dont_write_bytecode = True  # keep scripts/__pycache__ out of the repo tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import claim  # noqa: E402

R1 = "11111111-1111-4111-8111-111111111111"
R2 = "22222222-2222-4222-8222-222222222222"
R3 = "33333333-3333-4333-8333-333333333333"
IDENT = "ZTR-1"


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def claim_body(lane, run=None):
    first = f"{claim.MARK} lane={lane}" + (f" run={run}" if run else "")
    return first + "\n\nClaimed."


class FakeLinear:
    """In-memory Linear stand-in: a newest-first comment log plus a state name."""

    def __init__(self):
        self.comments = []
        self.state = "Ready"
        self.state_lookups = []   # (team key, state name) pairs claim.py asked to resolve

    def add(self, body, minutes_ago=0):
        ts = iso(datetime.now(timezone.utc) - timedelta(minutes=minutes_ago))
        self.comments.insert(0, {"body": body, "createdAt": ts})

    def issue(self, ident):
        return {"id": "fake", "identifier": ident, "state": {"name": self.state},
                "comments": {"nodes": self.comments}}

    def gql(self, q, v=None):
        if "commentCreate" in q:
            self.add(v["b"])
            return {"commentCreate": {"success": True}}
        if "workflowStates" in q:
            # Real Linear resolves the state on the identifier's own board; the id is
            # opaque, so the fake mints one that carries the resolved name back.
            self.state_lookups.append((v["k"], v["n"]))
            return {"workflowStates": {"nodes": [{"id": f"state:{v['n']}", "name": v["n"]}]}}
        if "issueUpdate" in q:
            assert v["s"].startswith("state:"), f"state id must come from a lookup, got {v['s']!r}"
            self.state = v["s"].split(":", 1)[1]
            return {"issueUpdate": {"success": True}}
        raise AssertionError(f"unexpected gql: {q[:80]}")

    def holder(self):
        return claim.holder(self.issue(IDENT))


def run_cli(fake, *argv):
    """Invoke claim.main() against the fake; returns (exit_code, stdout, stderr).
    SystemExit with a string message surfaces as that string in exit_code."""
    out, err, code = io.StringIO(), io.StringIO(), None
    with mock.patch.object(claim, "issue", fake.issue), \
         mock.patch.object(claim, "gql", fake.gql), \
         mock.patch.object(sys, "argv", ["claim.py", *argv]), \
         redirect_stdout(out), redirect_stderr(err):
        try:
            claim.main()
        except SystemExit as e:
            code = e.code if e.code is not None else 0
    return code, out.getvalue(), err.getvalue()


class ClaimMutexTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeLinear()

    # --- criterion 2: claim refuses a live claim with a different run, same role ---

    def test_same_role_different_run_claim_refused(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=5)
        n = len(self.fake.comments)
        for argv in [("claim", IDENT, "implementer", "", "In-Work", "--run", R2),
                     ("claim", IDENT, "implementer", "", "In-Work")]:  # minted run != R1 too
            code, out, _ = run_cli(self.fake, *argv)
            self.assertIsInstance(code, str)
            self.assertIn("REFUSED", code)
            self.assertIn(R1, code)                       # refusal names the holder's run
            self.assertEqual(n, len(self.fake.comments))  # nothing posted
        self.assertEqual(self.fake.holder()["run"], R1)

    def test_holder_run_can_reclaim_and_claim_prints_the_run(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=5)
        code, out, _ = run_cli(self.fake, "claim", IDENT, "implementer", "", "--run", R1)
        self.assertIsNone(code)
        self.assertIn(f"run={R1}", out)
        self.assertIn("--run " + R1, out)                 # hand-off hint for beat/release
        self.assertEqual(self.fake.holder()["run"], R1)

    # --- criterion 4/5: a race loser's release cannot dissolve the winner's claim ---

    def test_losers_release_cannot_dissolve_winners_claim(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=10)  # earliest = winner
        self.fake.add(claim_body("implementer", R2), minutes_ago=9)   # race loser
        self.assertEqual(self.fake.holder()["run"], R1)
        code, _, _ = run_cli(self.fake, "release", IDENT, "implementer", "lost race", "--run", R2)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        self.assertIn("refusing to dissolve another lane's claim", code)
        self.assertEqual(self.fake.holder()["run"], R1)   # winner untouched
        self.assertEqual(self.fake.state, "Ready")        # no state move happened
        # even if a mismatched RELEASE marker somehow lands (old copy, hand-rolled),
        # the replay ignores it: only a same-run RELEASE cancels a run-scoped claim
        self.fake.add(f"{claim.REL} lane=implementer run={R2} -> Ready\n\nstray")
        self.assertEqual(self.fake.holder()["run"], R1)
        # and the winner's own release dissolves it
        self.fake.add(f"{claim.REL} lane=implementer run={R1} -> Ready\n\ndone")
        self.assertIsNone(self.fake.holder())

    def test_release_without_run_refused_for_run_scoped_claim(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=3)
        code, _, _ = run_cli(self.fake, "release", IDENT, "implementer", "done", "QA-Review")
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        self.assertEqual(self.fake.holder()["run"], R1)

    def test_winners_release_dissolves_and_marker_carries_the_run(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=3)
        code, out, _ = run_cli(self.fake, "release", IDENT, "implementer", "PR #1", "QA-Review", "--run", R1)
        self.assertIsNone(code)
        self.assertIn(f"run={R1}", out)
        self.assertIsNone(self.fake.holder())
        self.assertEqual(self.fake.state, "QA Review")   # resolved on the ticket's own board
        first = self.fake.comments[0]["body"].split("\n", 1)[0]
        self.assertIn(f"run={R1}", first)
        self.assertIn(claim.REL, self.fake.comments[0]["body"])  # old copies still see a release

    # --- criterion 3: check prints the holder's run and tells self from rival ---

    def test_check_distinguishes_self_from_rival(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=4)
        code, out, _ = run_cli(self.fake, "check", IDENT)
        self.assertEqual(code, 1)
        self.assertIn(R1, out)                            # holder's run is printed
        code, out, _ = run_cli(self.fake, "check", IDENT, "--run", R1)
        self.assertEqual(code, 1)
        self.assertIn("YOUR claim", out)
        code, out, _ = run_cli(self.fake, "check", IDENT, "--run", R2)
        self.assertEqual(code, 1)
        self.assertIn("DIFFERENT run", out)
        self.assertIn("stand down", out)

    # --- earliest live claim wins; stale takeover still works ---

    def test_earliest_live_claim_wins_a_race(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=10)
        self.fake.add(claim_body("implementer", R2), minutes_ago=9)
        self.fake.add(f"{claim.MARK} lane=implementer run={R2} · heartbeat\n\nR2 alive", minutes_ago=2)
        self.fake.add(f"{claim.MARK} lane=implementer run={R1} · heartbeat\n\nR1 alive", minutes_ago=1)
        self.assertEqual(self.fake.holder()["run"], R1)   # NOT R2 (newest-first would pick R2)

    def test_stale_claim_is_taken_over_and_the_zombie_cannot_return(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=95)  # silent since
        code, out, _ = run_cli(self.fake, "claim", IDENT, "implementer", "", "In-Work", "--run", R2)
        self.assertIsNone(code)
        self.assertIn("Taking over", self.fake.comments[0]["body"])
        self.assertEqual(self.fake.holder()["run"], R2)
        self.assertEqual(self.fake.state, "In Work")
        # the old claim lane coming back to life must not snatch the ticket back
        code, _, _ = run_cli(self.fake, "beat", IDENT, "implementer", "zombie", "--run", R1)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        self.fake.add(f"{claim.MARK} lane=implementer run={R1} · heartbeat\n\nzombie", minutes_ago=0)
        self.assertEqual(self.fake.holder()["run"], R2)

    # --- beats are run-scoped ---

    def test_beat_requires_the_holder_run_and_refuses_a_wrong_one(self):
        self.fake.add(claim_body("implementer", R1), minutes_ago=5)
        code, _, _ = run_cli(self.fake, "beat", IDENT, "implementer", "no run given")
        self.assertIsInstance(code, str)
        self.assertIn(R1, code)                           # refusal recovers the run
        code, _, _ = run_cli(self.fake, "beat", IDENT, "implementer", "wrong", "--run", R2)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        code, out, _ = run_cli(self.fake, "beat", IDENT, "implementer", "progress", "--run", R1)
        self.assertIsNone(code)
        first = self.fake.comments[0]["body"].split("\n", 1)[0]
        self.assertIn(f"run={R1}", first)
        self.assertLess(self.fake.holder()["idle_min"], 1)  # beat refreshed the claim

    # --- backwards compatibility with run-less (legacy) markers ---

    def test_legacy_claim_from_another_lane_still_blocks(self):
        self.fake.add(claim_body("reviewer", None), minutes_ago=5)
        code, _, _ = run_cli(self.fake, "claim", IDENT, "implementer", "", "In-Work")
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        self.assertIn("run-less legacy claim", code)

    def test_legacy_markers_still_parse(self):
        self.fake.add(claim_body("implementer", None), minutes_ago=50)
        self.fake.add("unrelated progress note mentioning lane=implementer", minutes_ago=5)
        h = self.fake.holder()
        self.assertEqual((h["lane"], h["run"]), ("implementer", None))
        self.assertLess(h["idle_min"], 10)                # old lane= freshness semantics
        self.fake.add(f"{claim.REL} lane=implementer -> Ready\n\nlegacy release")
        self.assertIsNone(self.fake.holder())             # legacy RELEASE dissolves any holder
        code, out, _ = run_cli(self.fake, "check", IDENT)
        self.assertIsNone(code)
        self.assertIn("FREE", out)

    def test_legacy_claim_accepts_run_less_beats_and_upgrades_on_reclaim(self):
        self.fake.add(claim_body("implementer", None), minutes_ago=30)
        code, out, _ = run_cli(self.fake, "check", IDENT, "--run", R1)
        self.assertEqual(code, 1)
        self.assertIn("run-less claim", out)              # migration hint, not "stand down"
        self.assertIn("re-claim", out)
        code, out, _ = run_cli(self.fake, "beat", IDENT, "implementer", "old-style beat still works")
        self.assertIsNone(code)                           # migration: no --run needed pre-upgrade
        self.assertNotIn("run=", self.fake.comments[0]["body"].split("\n", 1)[0])
        code, out, _ = run_cli(self.fake, "claim", IDENT, "implementer", "", "In-Work", "--run", R1)
        self.assertIsNone(code)
        self.assertIn("Upgrading", self.fake.comments[0]["body"])
        self.assertEqual(self.fake.holder()["run"], R1)   # same lane, now run-scoped

    def test_legacy_release_by_same_lane_still_works_but_other_lane_warns(self):
        self.fake.add(claim_body("implementer", None), minutes_ago=5)
        code, _, err = run_cli(self.fake, "release", IDENT, "reviewer", "handoff", "Ready")
        self.assertIsNone(code)                           # legacy semantics preserved
        self.assertIn("WARNING", err)
        self.assertIsNone(self.fake.holder())

    # --- marker format stays parseable by pre-run copies of this script ---

    def test_new_markers_stay_parseable_by_old_copies(self):
        code, _, _ = run_cli(self.fake, "claim", IDENT, "implementer", "", "In-Work", "--run", R1)
        self.assertIsNone(code)
        body = self.fake.comments[0]["body"]
        self.assertIn(claim.MARK, body)                                       # old MARK detection
        self.assertEqual(re.search(r"lane=(\S+)", body).group(1), "implementer")  # old lane regex
        first = body.split("\n", 1)[0]
        self.assertRegex(first, rf"^{re.escape(claim.MARK)} lane=\S+ run=\S+$")


class ClaimWindowTest(unittest.TestCase):
    """Claim windows are the provenance the strict-dual fence reads to tell a
    genuine review verdict from one forged under another lane's run id."""

    def setUp(self):
        self.fake = FakeLinear()

    def windows(self):
        return claim.windows(self.fake.issue(IDENT))

    def test_release_closes_the_window_and_a_reclaim_opens_a_new_one(self):
        self.fake.add(claim_body("reviewer", R1), minutes_ago=90)
        self.fake.add(f"{claim.REL} lane=reviewer run={R1}", minutes_ago=80)
        self.fake.add(claim_body("reviewer", R1), minutes_ago=70)
        self.fake.add(f"{claim.REL} lane=reviewer run={R1}", minutes_ago=60)
        got = self.windows()
        self.assertEqual(len(got), 2, "claim -> release -> claim is two windows, not one")
        for w in got:
            self.assertEqual(w["run"], R1)
            self.assertIsNotNone(w["end"])
        self.assertLess(got[0]["end"], got[1]["start"])

    def test_beats_extend_one_window_rather_than_opening_more(self):
        self.fake.add(claim_body("reviewer", R1), minutes_ago=50)
        self.fake.add(f"{claim.MARK} lane=reviewer run={R1}", minutes_ago=40)  # re-claim/refresh
        self.assertEqual(len(self.windows()), 1)

    def test_an_abandoned_claim_stops_vouching_after_it_goes_stale(self):
        # Never released, silent for hours. Left open it would vouch for a verdict
        # posted at any future time — a standing credential for a forger.
        self.fake.add(claim_body("reviewer", R1), minutes_ago=600)
        w = self.windows()[0]
        self.assertIsNotNone(w["end"], "a dead claim must not leave an open-ended window")
        span = claim.parse_ts(w["end"]) - claim.parse_ts(w["start"])
        self.assertEqual(span, timedelta(minutes=claim.STALE_MINUTES))

    def test_a_live_claim_stays_open(self):
        self.fake.add(claim_body("reviewer", R1), minutes_ago=5)
        self.assertIsNone(self.windows()[0]["end"])

    def test_a_legacy_release_closes_every_open_window(self):
        self.fake.add(claim_body("reviewer", R1), minutes_ago=30)
        self.fake.add(claim_body("implementer", R2), minutes_ago=25)
        self.fake.add(f"{claim.REL} lane=reviewer", minutes_ago=20)   # run-less legacy
        self.assertTrue(all(w["end"] is not None for w in self.windows()))

    def test_verdict_forged_under_a_released_run_falls_outside_its_window(self):
        """The PR #1794 shape, in claim-trail terms."""
        self.fake.add(claim_body("reviewer", R1), minutes_ago=100)
        self.fake.add(f"{claim.REL} lane=reviewer run={R1}", minutes_ago=60)
        w = self.windows()[0]
        genuine = iso(datetime.now(timezone.utc) - timedelta(minutes=65))
        forged = iso(datetime.now(timezone.utc) - timedelta(minutes=20))
        self.assertTrue(w["start"] <= genuine <= w["end"])
        self.assertGreater(forged, w["end"])

    # --- F2: windows() applies earliest-wins per LANE NAME ---

    def test_forged_same_lane_duplicate_gets_no_window_while_holder_is_live(self):
        """A second reviewer-A CLAIM under a DIFFERENT run, while the first is still
        live, is a race-loser and opens NO window. The pre-F2 code keyed windows by
        run and minted one per CLAIM, so one Linear comment on the shared token bought
        a vouching window — mint it, post two head-pinned PASSes under it, clear dual."""
        self.fake.add(claim_body("reviewer-A", R1), minutes_ago=20)   # holder, live
        self.fake.add(claim_body("reviewer-A", R2), minutes_ago=10)   # forged duplicate
        got = self.windows()
        self.assertEqual(len(got), 1, "the race-loser duplicate opens no window")
        self.assertEqual(got[0]["run"], R1)
        self.assertIsNone(got[0]["end"])                              # holder still live

    def test_two_reviewer_sublanes_each_keep_their_own_window(self):
        """Distinct lane names (reviewer-A vs reviewer-B) are independent, so an honest
        dual review with two reviewer sub-lanes coexists — two windows, two runs."""
        self.fake.add(claim_body("reviewer-A", R1), minutes_ago=20)
        self.fake.add(claim_body("reviewer-B", R2), minutes_ago=18)
        got = self.windows()
        self.assertEqual(len(got), 2)
        self.assertEqual({w["run"] for w in got}, {R1, R2})
        self.assertEqual({w["lane"] for w in got}, {"reviewer-A", "reviewer-B"})

    def test_a_stale_same_lane_claim_is_taken_over_by_a_new_run(self):
        """A different run on the SAME lane DOES open a window when the holder had
        already gone stale — the earliest-wins takeover, mirroring holder(). The dead
        window closes at its last refresh + stale, never overlapping the live one."""
        self.fake.add(claim_body("reviewer-A", R1), minutes_ago=200)  # long silent -> stale
        self.fake.add(claim_body("reviewer-A", R2), minutes_ago=5)    # takes over
        got = self.windows()
        self.assertEqual(len(got), 2, "stale holder -> the new run takes over with its own window")
        first = next(w for w in got if w["run"] == R1)
        second = next(w for w in got if w["run"] == R2)
        self.assertIsNotNone(first["end"], "the stale window closes")
        self.assertIsNone(second["end"], "the live takeover stays open")
        self.assertLessEqual(first["end"], second["start"])



class ClaimCoholdTest(unittest.TestCase):
    """Reviewer-A/B co-hold; every other role stays single-holder."""

    def setUp(self):
        self.fake = FakeLinear()

    def holders(self):
        return claim.holders(self.fake.issue(IDENT))

    def test_reviewer_ab_cohold_accepted(self):
        """reviewer-A and reviewer-B may both hold; check names both; beats/releases are run-scoped."""
        code, out, _ = run_cli(self.fake, "claim", IDENT, "reviewer-A", "--run", R1)
        self.assertIsNone(code)
        self.assertIn(R1, out)
        code, out, _ = run_cli(self.fake, "claim", IDENT, "reviewer-B", "--run", R2)
        self.assertIsNone(code, out)
        self.assertIn("[co-hold]", out)
        self.assertIn(R2, out)
        hs = self.holders()
        self.assertEqual(len(hs), 2)
        self.assertEqual({h["lane"] for h in hs}, {"reviewer-A", "reviewer-B"})
        self.assertEqual({h["run"] for h in hs}, {R1, R2})
        # check lists both and marks each run as own
        code, out, _ = run_cli(self.fake, "check", IDENT)
        self.assertEqual(code, 1)
        self.assertIn("reviewer-A", out)
        self.assertIn("reviewer-B", out)
        self.assertIn(R1, out)
        self.assertIn(R2, out)
        code, out, _ = run_cli(self.fake, "check", IDENT, "--run", R1)
        self.assertEqual(code, 1)
        self.assertIn("YOUR claim", out)
        code, out, _ = run_cli(self.fake, "check", IDENT, "--run", R2)
        self.assertEqual(code, 1)
        self.assertIn("YOUR claim", out)
        # each side can beat under its own run
        code, _, _ = run_cli(self.fake, "beat", IDENT, "reviewer-A", "A progress", "--run", R1)
        self.assertIsNone(code)
        code, _, _ = run_cli(self.fake, "beat", IDENT, "reviewer-B", "B progress", "--run", R2)
        self.assertIsNone(code)
        # A release dissolves only A; B remains; ticket state stays put under co-hold
        self.fake.state = "QA Review"
        code, out, _ = run_cli(self.fake, "release", IDENT, "reviewer-A", "A done", "Ready", "--run", R1)
        self.assertIsNone(code)
        self.assertIn("state unchanged", out)
        self.assertEqual(self.fake.state, "QA Review")
        hs = self.holders()
        self.assertEqual(len(hs), 1)
        self.assertEqual(hs[0]["run"], R2)
        self.assertEqual(hs[0]["lane"], "reviewer-B")
        # last holder release moves state
        code, out, _ = run_cli(self.fake, "release", IDENT, "reviewer-B", "B done", "QA-Review", "--run", R2)
        self.assertIsNone(code)
        self.assertIn("-> QA-Review", out)
        self.assertEqual(self.fake.state, "QA Review")
        self.assertEqual(self.holders(), [])

    def test_third_reviewer_refused(self):
        """A third concurrent reviewer (same letter re-run, or plain reviewer) is refused."""
        self.fake.add(claim_body("reviewer-A", R1), minutes_ago=10)
        self.fake.add(claim_body("reviewer-B", R2), minutes_ago=8)
        n = len(self.fake.comments)
        # same letter, different run
        code, _, _ = run_cli(self.fake, "claim", IDENT, "reviewer-A", "--run", R3)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        # plain reviewer role is not a co-hold letter
        code, _, _ = run_cli(self.fake, "claim", IDENT, "reviewer", "--run", R3)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        self.assertEqual(n, len(self.fake.comments))
        self.assertEqual({h["run"] for h in self.holders()}, {R1, R2})

    def test_non_reviewer_second_holder_refused(self):
        """implementer/merger cannot join a live reviewer co-hold or each other."""
        self.fake.add(claim_body("reviewer-A", R1), minutes_ago=5)
        n = len(self.fake.comments)
        for role in ("implementer", "merger", "sweeper", "reviewer"):
            code, _, _ = run_cli(self.fake, "claim", IDENT, role, "--run", R2)
            self.assertIsInstance(code, str, role)
            self.assertIn("REFUSED", code, role)
        self.assertEqual(n, len(self.fake.comments))
        # implementer alone still single-holder vs another implementer
        self.fake = FakeLinear()
        self.fake.add(claim_body("implementer", R1), minutes_ago=5)
        code, _, _ = run_cli(self.fake, "claim", IDENT, "implementer", "", "In-Work", "--run", R2)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        code, _, _ = run_cli(self.fake, "claim", IDENT, "merger", "--run", R2)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        # merger alone still single-holder
        self.fake = FakeLinear()
        self.fake.add(claim_body("merger", R1), minutes_ago=5)
        code, _, _ = run_cli(self.fake, "claim", IDENT, "merger", "--run", R2)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)
        code, _, _ = run_cli(self.fake, "claim", IDENT, "reviewer-A", "--run", R2)
        self.assertIsInstance(code, str)
        self.assertIn("REFUSED", code)

    def test_cohold_windows_two_distinct_runs_for_fence(self):
        """Two co-hold claims produce two open windows with distinct runs (fence input)."""
        code, _, _ = run_cli(self.fake, "claim", IDENT, "reviewer-A", "--run", R1)
        self.assertIsNone(code)
        code, _, _ = run_cli(self.fake, "claim", IDENT, "reviewer-B", "--run", R2)
        self.assertIsNone(code)
        wins = claim.windows(self.fake.issue(IDENT))
        self.assertEqual(len(wins), 2)
        self.assertEqual({w["run"] for w in wins}, {R1, R2})
        self.assertEqual({w["lane"] for w in wins}, {"reviewer-A", "reviewer-B"})
        self.assertTrue(all(w["end"] is None for w in wins))
        # one side releasing leaves the other window open
        code, _, _ = run_cli(self.fake, "release", IDENT, "reviewer-B", "B done", "QA-Review", "--run", R2)
        self.assertIsNone(code)
        wins = claim.windows(self.fake.issue(IDENT))
        open_w = [w for w in wins if w["end"] is None]
        closed_w = [w for w in wins if w["end"] is not None]
        self.assertEqual(len(open_w), 1)
        self.assertEqual(open_w[0]["run"], R1)
        self.assertEqual(len(closed_w), 1)
        self.assertEqual(closed_w[0]["run"], R2)

    def test_check_signals_open_cohold_slot(self):
        """With only reviewer-A live, check advertises the open reviewer-B co-hold slot."""
        self.fake.add(claim_body("reviewer-A", R1), minutes_ago=5)
        code, out, _ = run_cli(self.fake, "check", IDENT)
        self.assertEqual(code, 1)
        self.assertIn("co-hold open for lane=reviewer-B", out)
        code, out, _ = run_cli(self.fake, "check", IDENT, "--run", R3)
        self.assertEqual(code, 1)
        self.assertIn("co-hold lane=reviewer-B", out)

class TeamRoutingTest(unittest.TestCase):
    """ZPAY-216 AC1/AC2: team + workflow state come from the typed identifier.

    The defect: a pinned ZTR team UUID made every `ZPAY-<n>` call resolve `ZTR-<n>`.
    It failed silently on the read side (a real ticket came back, just the wrong
    team's) and took down the strict-dual fence, which shells `claim.py windows`.
    """

    def setUp(self):
        self.fake = FakeLinear()

    def test_issue_lookup_filters_by_the_identifiers_own_team_key(self):
        seen = []

        def gql(q, v=None):
            seen.append((q, v))
            return {"issues": {"nodes": [{"id": "fake", "identifier": "ZPAY-216",
                                          "state": {"name": "In Work"},
                                          "comments": {"nodes": []}}]}}

        with mock.patch.object(claim, "gql", gql):
            it = claim.issue("ZPAY-216")
        self.assertEqual(it["identifier"], "ZPAY-216")
        _, variables = seen[0]
        self.assertEqual(variables["k"], "ZPAY", "the query must filter on the typed team key")
        self.assertEqual(variables["n"], 216)
        self.assertNotIn("t", variables, "a pinned team id is the misroute defect")

    def test_cross_team_resolution_is_refused(self):
        """The backstop for the defect itself: ZTR-216 answering for ZPAY-216 refuses."""
        def gql(q, v=None):
            return {"issues": {"nodes": [{"id": "fake", "identifier": "ZTR-216",
                                          "state": {"name": "In Work"},
                                          "comments": {"nodes": []}}]}}

        with mock.patch.object(claim, "gql", gql), self.assertRaises(SystemExit) as caught:
            claim.issue("ZPAY-216")
        self.assertIn("wrong team, refusing", str(caught.exception))

    def test_state_is_resolved_on_the_tickets_own_board(self):
        ident = "ZPAY-216"
        self.fake.add(claim_body("implementer", R1), minutes_ago=3)
        code, out, _ = run_cli(self.fake, "release", ident, "implementer", "PR #1",
                               "QA-Review", "--run", R1)
        self.assertIsNone(code)
        self.assertEqual(self.fake.state_lookups, [("ZPAY", "QA Review")])
        self.assertEqual(self.fake.state, "QA Review")

    def test_merger_and_sweeper_terminal_states_are_reachable(self):
        for target in ("Done", "Triage", "Canceled", "Duplicate", "Backlog", "In-Work"):
            fake = FakeLinear()
            fake.add(claim_body("merger", R1), minutes_ago=1)
            code, _, _ = run_cli(fake, "release", "ZPAY-9", "merger", "done", target, "--run", R1)
            self.assertIsNone(code, f"{target} must be reachable, got {code!r}")
            self.assertEqual(fake.state_lookups[0][0], "ZPAY")
        code, _, _ = run_cli(self.fake, "release", "ZPAY-9", "merger", "x", "Shipped", "--run", R1)
        self.assertIsInstance(code, str)
        self.assertIn("unknown state Shipped", code)

    def test_selftest_is_offline_and_guards_against_a_pinned_uuid_regression(self):
        out = io.StringIO()
        with redirect_stdout(out):
            claim.selftest()          # no gql patch: selftest must touch no network
        self.assertIn("selftest ok", out.getvalue())
        self.assertEqual(claim._pinned_uuids(), [])
        # Reintroducing a pinned team/state UUID is exactly the ZPAY-216 defect.
        with mock.patch.dict(claim.__dict__, {"TEAM_ID": "ffa2ce06-9072-47ad-b0aa-876d66e049fb"}):
            self.assertEqual(claim._pinned_uuids(), ["TEAM_ID"])
            with self.assertRaises(AssertionError):
                claim.selftest()


if __name__ == "__main__":
    unittest.main(verbosity=2)
