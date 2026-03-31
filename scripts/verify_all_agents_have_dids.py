#!/usr/bin/env python3
"""
verify_all_agents_have_dids.py — Observer Protocol health-check script

Verifies that every verified agent in the DB has:
  1. An agent_did column set
  2. A did_document column set (non-null JSONB)
  3. The DID Document contains a valid verificationMethod with publicKeyMultibase

Optionally back-fills DIDs for agents that have a public_key but no agent_did,
using the same did_document_builder logic as the registration endpoint.

Usage:
    # Report only (default)
    python3 scripts/verify_all_agents_have_dids.py

    # Report + back-fill missing DIDs
    python3 scripts/verify_all_agents_have_dids.py --backfill

    # Only back-fill specific agent(s)
    python3 scripts/verify_all_agents_have_dids.py --backfill --agent-id <id>

Environment variables required:
    DATABASE_URL    PostgreSQL connection string
"""

import argparse
import json
import os
import sys

# Allow running from repo root or scripts/ directory
_script_dir = os.path.dirname(os.path.abspath(__file__))
_api_dir = os.path.join(os.path.dirname(_script_dir), "api")
if _api_dir not in sys.path:
    sys.path.insert(0, _api_dir)

import psycopg2
import psycopg2.extras


def _get_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("ERROR: DATABASE_URL environment variable is not set.")
    return url


def _check_did_document(did_doc: dict, agent_id: str) -> list:
    """Return a list of errors in the DID Document structure, or [] if valid."""
    errors = []
    if not isinstance(did_doc, dict):
        return ["did_document is not a dict"]
    if not did_doc.get("id", "").startswith("did:"):
        errors.append("did_document.id is missing or not a DID")
    vms = did_doc.get("verificationMethod", [])
    if not vms:
        errors.append("verificationMethod array is empty")
    for vm in vms:
        if not vm.get("publicKeyMultibase", "").startswith("z"):
            errors.append(
                f"verificationMethod {vm.get('id', '?')} "
                f"publicKeyMultibase does not start with 'z'"
            )
    return errors


def _backfill_agent(conn, agent_id: str, public_key: str) -> str:
    """
    Generate and store a DID + DID Document for an agent that lacks one.

    Returns a status string for reporting.
    """
    from did_document_builder import build_agent_did, build_agent_did_document

    agent_did = build_agent_did(agent_id)
    did_doc = build_agent_did_document(agent_id, public_key)

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE observer_agents
            SET agent_did = %s,
                did_document = %s,
                did_updated_at = NOW()
            WHERE agent_id = %s
              AND agent_did IS NULL
            """,
            (agent_did, json.dumps(did_doc), agent_id),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return "skipped (DID already set by concurrent writer)"
        return f"back-filled → {agent_did}"
    except Exception as exc:
        conn.rollback()
        return f"ERROR: {exc}"
    finally:
        cursor.close()


def run(backfill: bool = False, target_agent_id: str = None):
    db_url = _get_db_url()
    conn = psycopg2.connect(db_url)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        if target_agent_id:
            cursor.execute(
                """
                SELECT agent_id, verified, public_key, agent_did, did_document
                FROM observer_agents
                WHERE agent_id = %s
                """,
                (target_agent_id,),
            )
        else:
            cursor.execute(
                """
                SELECT agent_id, verified, public_key, agent_did, did_document
                FROM observer_agents
                ORDER BY agent_id
                """
            )
        agents = cursor.fetchall()
    finally:
        cursor.close()

    total = len(agents)
    verified_agents = [a for a in agents if a["verified"]]
    unverified_agents = [a for a in agents if not a["verified"]]

    print(f"Observer Protocol — DID Health Check")
    print(f"{'='*60}")
    print(f"Total agents:    {total}")
    print(f"  Verified:      {len(verified_agents)}")
    print(f"  Unverified:    {len(unverified_agents)}")
    print()

    # ── Analyse each agent ────────────────────────────────────────────────────
    ok = []
    missing_did = []
    bad_doc = []

    for agent in agents:
        aid = agent["agent_id"]
        v = "✓" if agent["verified"] else "○"

        if not agent["agent_did"]:
            missing_did.append(agent)
            continue

        did_doc = agent["did_document"]
        if isinstance(did_doc, str):
            try:
                did_doc = json.loads(did_doc)
            except Exception:
                bad_doc.append((agent, ["did_document is not valid JSON"]))
                continue
        if not isinstance(did_doc, dict):
            did_doc = dict(did_doc) if did_doc else {}

        doc_errors = _check_did_document(did_doc, aid)
        if doc_errors:
            bad_doc.append((agent, doc_errors))
        else:
            ok.append(agent)

    # ── Report ────────────────────────────────────────────────────────────────
    print(f"DID status:")
    print(f"  OK (DID + valid DID Document):   {len(ok)}")
    print(f"  Missing DID:                     {len(missing_did)}")
    print(f"  Invalid DID Document:            {len(bad_doc)}")
    print()

    if missing_did:
        print("Agents missing DID:")
        for a in missing_did:
            v = "✓" if a["verified"] else "○"
            has_key = "has public_key" if a["public_key"] else "NO public_key"
            print(f"  [{v}] {a['agent_id']}  ({has_key})")
        print()

    if bad_doc:
        print("Agents with invalid DID Document:")
        for a, errs in bad_doc:
            v = "✓" if a["verified"] else "○"
            print(f"  [{v}] {a['agent_id']}")
            for e in errs:
                print(f"        • {e}")
        print()

    # ── Back-fill ────────────────────────────────────────────────────────────
    if backfill:
        to_backfill = [
            a for a in missing_did
            if a["public_key"]  # can't build DID Document without a public key
        ]
        no_key = [a for a in missing_did if not a["public_key"]]

        if no_key:
            print(f"Skipping {len(no_key)} agent(s) with no public_key (cannot build DID Document):")
            for a in no_key:
                print(f"  {a['agent_id']}")
            print()

        if to_backfill:
            print(f"Back-filling {len(to_backfill)} agent(s)...")
            for a in to_backfill:
                try:
                    status = _backfill_agent(conn, a["agent_id"], a["public_key"])
                except ValueError as e:
                    status = f"skipped (unparseable public_key: {e})"
                print(f"  {a['agent_id']}: {status}")
            print()
        else:
            print("Nothing to back-fill.")

    conn.close()

    # ── Exit code ────────────────────────────────────────────────────────────
    problems = len(missing_did) + len(bad_doc)
    if problems == 0:
        print("All agents have valid DIDs. ✓")
        return 0
    else:
        print(
            f"WARNING: {problems} agent(s) need attention. "
            f"Run with --backfill to fix missing DIDs."
        )
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify (and optionally back-fill) DIDs for all Observer Protocol agents."
    )
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="Generate and store DIDs for agents that are missing them.",
    )
    parser.add_argument(
        "--agent-id",
        metavar="AGENT_ID",
        default=None,
        help="Limit check/backfill to a single agent.",
    )
    args = parser.parse_args()
    sys.exit(run(backfill=args.backfill, target_agent_id=args.agent_id))
