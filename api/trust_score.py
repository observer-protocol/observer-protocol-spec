"""
AT-ARS-1.0 trust score computation.

Extracted from api-server-v2.py for importability. This is the canonical
trust score computation — all consumers (TRON endpoint, generalized
endpoint, profile aggregation) import from here.

Do not modify the scoring math without a Tier 3 review.
"""

from datetime import datetime, timezone


def compute_tron_trust_score(metrics: dict) -> dict:
    """Compute trust score from TRON metrics using weighted components."""
    if not metrics or not metrics.get('agent_id'):
        return {
            "trust_score": 0.0,
            "components": {}
        }

    # Weights per spec
    weights = {
        "receipts": 0.25,
        "counterparties": 0.25,
        "org": 0.20,
        "recency": 0.15,
        "volume": 0.15
    }

    # Receipt score (logarithmic scale, max 50 receipts = 100%)
    receipt_count = metrics.get('tron_receipt_count', 0)
    receipt_score = min(100, (receipt_count / 50) * 100) if receipt_count > 0 else 0

    # Counterparty score (diversity, max 20 unique = 100%)
    counterparty_count = metrics.get('unique_tron_counterparties', 0)
    counterparty_score = min(100, (counterparty_count / 20) * 100) if counterparty_count > 0 else 0

    # Organization score
    org_count = metrics.get('org_affiliated_count', 0)
    org_score = 100 if org_count > 0 else 50  # Boost for org affiliation

    # Recency score (hours since last activity)
    last_tx = metrics.get('last_tron_tx')
    if last_tx:
        try:
            last_dt = datetime.fromisoformat(str(last_tx).replace('Z', '+00:00'))
            hours_ago = (datetime.now(timezone.utc) - last_dt).total_seconds() / 3600
            recency_score = max(0, 100 - (hours_ago / 24) * 10)  # -10% per day
        except Exception:
            recency_score = 50
    else:
        recency_score = 0

    # Volume score (combined TRX + stablecoin volume)
    trx_vol = float(metrics.get('total_trx_volume', 0) or 0)
    stable_vol = float(metrics.get('total_stablecoin_volume', 0) or 0)
    total_usd_estimate = (trx_vol / 100) + stable_vol  # Rough TRX price estimate
    volume_score = min(100, (total_usd_estimate / 10000) * 100)  # $10k = 100%

    # Compute weighted total
    trust_score = (
        receipt_score * weights['receipts'] +
        counterparty_score * weights['counterparties'] +
        org_score * weights['org'] +
        recency_score * weights['recency'] +
        volume_score * weights['volume']
    )

    return {
        "trust_score": round(trust_score, 2),
        "components": {
            "receipt_score": round(receipt_score, 2),
            "counterparty_score": round(counterparty_score, 2),
            "org_score": round(org_score, 2),
            "recency_score": round(recency_score, 2),
            "volume_score": round(volume_score, 2)
        }
    }
