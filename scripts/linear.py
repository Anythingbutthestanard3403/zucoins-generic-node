#!/usr/bin/env python3
"""Linear ops for the Zutopia org. Token from .secrets.env (`linear=`).

Usage:
  linear.py get ZTR-12                 # print title, state, labels, description
  linear.py comment ZTR-12 "body"      # add markdown comment (body may be - for stdin)
  linear.py state ZTR-12 "In Work"     # set workflow state
  linear.py selftest                   # offline check of the routing logic

The team and the workflow state are resolved from what the caller typed, never from a
hardcoded UUID: a pinned team/state UUID silently keeps routing at the old team after a
migration, which is how ZTR calls ended up landing on retired ZUP tickets.
"""
import json
import os
import re
import sys
import urllib.request

# ZUP (zucoins-merchant-wallets' original team) is retired — refuse it rather than
# operating on its stale tickets. Any other team key routes by the identifier itself.
RETIRED_TEAMS = {"ZUP"}
# ZTR renamed its workflow states; keep the pre-migration names working for callers
# that still ask for them.
STATE_ALIASES = {
    "Todo": "Ready",
    "In Progress": "In Work",
    "In Review": "QA Review",
    "Verifying": "QA Review",
}


def token():
    path = os.path.join(os.path.dirname(__file__), "..", ".secrets.env")
    for line in open(path):
        if line.startswith("linear="):
            return line.split("=", 1)[1].strip()
    sys.exit("no linear token in .secrets.env")


def gql(query, variables=None):
    req = urllib.request.Request(
        "https://api.linear.app/graphql",
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        headers={"Authorization": token(), "Content-Type": "application/json"},
    )
    resp = json.load(urllib.request.urlopen(req))
    if resp.get("errors"):
        sys.exit(f"linear error: {resp['errors']}")
    return resp["data"]


def parse_identifier(identifier):
    """Split `ZTR-755` into its team key and number, rejecting anything ambiguous."""
    match = re.fullmatch(r"([A-Za-z]+)-(\d+)", (identifier or "").strip())
    if not match:
        sys.exit(f"bad issue identifier {identifier!r} — expected a full id like ZTR-755")
    key = match.group(1).upper()
    if key in RETIRED_TEAMS:
        sys.exit(f"team {key} is retired — use the ZTR identifier for this work")
    return key, int(match.group(2))


def issue_uuid(identifier):
    key, number = parse_identifier(identifier)
    data = gql(
        """query($key: String!, $n: Float) {
             issues(filter: {team: {key: {eq: $key}}, number: {eq: $n}}) {
               nodes { id identifier } } }""",
        {"key": key, "n": number},
    )
    nodes = data["issues"]["nodes"]
    if not nodes:
        sys.exit(f"issue {key}-{number} not found")
    issue = nodes[0]
    if issue["identifier"].upper() != f"{key}-{number}":
        sys.exit(
            f"cross-team mismatch: requested {key}-{number} but resolved "
            f"{issue['identifier']} — refusing to operate on the wrong team's issue"
        )
    return issue["id"]


def state_uuid(key, name):
    """Resolve a workflow state name on `key`'s own board, honouring the legacy aliases."""
    name = STATE_ALIASES.get(name, name)
    data = gql(
        """query($key: String!, $name: String!) {
             workflowStates(filter: {team: {key: {eq: $key}}, name: {eq: $name}}) {
               nodes { id name } } }""",
        {"key": key, "name": name},
    )
    nodes = data["workflowStates"]["nodes"]
    if not nodes:
        sys.exit(f"no workflow state named {name!r} on team {key}")
    return nodes[0]["id"], name


def selftest():
    assert parse_identifier("ZTR-755") == ("ZTR", 755)
    assert parse_identifier(" ztr-755 ") == ("ZTR", 755), "identifiers are case/space tolerant"
    for bad in ("755", "ZTR", "ZTR-", "ZTR-7x", "ZTR-755-1", "", None):
        try:
            parse_identifier(bad)
        except SystemExit:
            continue
        raise AssertionError(f"{bad!r} should have been rejected")
    try:
        parse_identifier("ZUP-755")
    except SystemExit:
        pass
    else:
        raise AssertionError("retired ZUP must be refused, not resolved")
    assert STATE_ALIASES["In Progress"] == "In Work"
    assert STATE_ALIASES["Verifying"] == "QA Review"
    assert "In Work" not in STATE_ALIASES, "canonical names must pass through untouched"
    print("selftest ok")


def main():
    if sys.argv[1:2] == ["selftest"]:
        return selftest()
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, ident = sys.argv[1], sys.argv[2]
    uuid = issue_uuid(ident)
    if cmd == "get":
        data = gql(
            """query($id: String!) { issue(id: $id) {
                 identifier title description
                 state { name } labels { nodes { name } }
                 comments { nodes { body createdAt user { name } } } } }""",
            {"id": uuid},
        )
        i = data["issue"]
        labels = ", ".join(l["name"] for l in i["labels"]["nodes"])
        print(f"{i['identifier']} · {i['title']}\nState: {i['state']['name']} · Labels: {labels}\n")
        print(i["description"] or "(no description)")
        for c in i["comments"]["nodes"]:
            print(f"\n--- comment ({c['createdAt']}, {(c.get('user') or {}).get('name')}):\n{c['body']}")
    elif cmd == "comment":
        body = sys.stdin.read() if sys.argv[3] == "-" else sys.argv[3]
        gql(
            "mutation($id: String!, $body: String!) { commentCreate(input: {issueId: $id, body: $body}) { success } }",
            {"id": uuid, "body": body},
        )
        print(f"commented on {ident}")
    elif cmd == "state":
        key, _ = parse_identifier(ident)
        state, name = state_uuid(key, sys.argv[3])
        gql(
            "mutation($id: String!, $state: String!) { issueUpdate(id: $id, input: {stateId: $state}) { success } }",
            {"id": uuid, "state": state},
        )
        print(f"{ident} -> {name}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
