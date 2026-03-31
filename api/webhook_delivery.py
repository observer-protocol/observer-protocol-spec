#!/usr/bin/env python3
"""
Webhook Delivery System — Observer Protocol

Delivers webhook notifications to registered endpoints with retry logic,
HMAC-SHA256 payload signing, and delivery tracking.

Environment Variables:
    DATABASE_URL           PostgreSQL connection string
    OP_WEBHOOK_TIMEOUT     Request timeout in seconds (default: 10)
    OP_WEBHOOK_MAX_RETRIES Maximum retry attempts (default: 3)
    OP_WEBHOOK_SECRET      Secret key for HMAC signatures
    OP_WEBHOOK_RETRY_DELAY Initial retry delay in seconds (default: 1)
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    aiohttp = None


class WebhookEventType(Enum):
    """Supported webhook event types."""
    # DID lifecycle (Layer 1)
    DID_REGISTERED = "did.registered"
    DID_ROTATED = "did.rotated"
    # VC/VP lifecycle (Layer 2)
    VC_ISSUED = "vc.issued"
    VP_SUBMITTED = "vp.submitted"
    # VAC lifecycle
    VAC_REVOKED = "vac.revoked"
    VAC_ISSUED = "vac.issued"
    VAC_REFRESHED = "vac.refreshed"
    # Attestation lifecycle
    ATTESTATION_ISSUED = "attestation.issued"
    ATTESTATION_REVOKED = "attestation.revoked"
    # Agent lifecycle
    AGENT_VERIFIED = "agent.verified"
    # Partner lifecycle
    PARTNER_REGISTERED = "partner.registered"


class WebhookStatus(Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class WebhookPayload:
    event_type: str
    timestamp: str
    data: Dict[str, Any]
    webhook_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "webhook_id": self.webhook_id,
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass
class WebhookDelivery:
    delivery_id: str
    webhook_id: str
    event_type: str
    url: str
    payload: str
    status: str
    created_at: str
    delivered_at: Optional[str] = None
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0


class WebhookSigner:
    def __init__(self, secret: Optional[str] = None):
        self.secret = secret or os.environ.get("OP_WEBHOOK_SECRET", "")

    def sign(self, payload: str) -> str:
        if not self.secret:
            return ""
        sig = hmac.new(
            self.secret.encode(), payload.encode(), hashlib.sha256
        ).digest()
        return base64.b64encode(sig).decode()

    def verify(self, payload: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class WebhookDeliverer:
    def __init__(
        self,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
        retry_delay: Optional[float] = None,
    ):
        self.timeout = timeout or int(os.environ.get("OP_WEBHOOK_TIMEOUT", "10"))
        self.max_retries = max_retries or int(os.environ.get("OP_WEBHOOK_MAX_RETRIES", "3"))
        self.retry_delay = retry_delay or float(os.environ.get("OP_WEBHOOK_RETRY_DELAY", "1"))
        self.signer = WebhookSigner()
        self._delivery_history: List[WebhookDelivery] = []

    async def send_webhook(
        self,
        url: str,
        payload: WebhookPayload,
        headers: Optional[Dict[str, str]] = None,
    ) -> WebhookDelivery:
        delivery_id = str(uuid.uuid4())
        payload_json = payload.to_json()
        signature = self.signer.sign(payload_json)

        request_headers = {
            "Content-Type": "application/json",
            "X-Webhook-ID": payload.webhook_id,
            "X-Event-Type": payload.event_type,
            "X-Delivery-ID": delivery_id,
            "X-Signature": signature,
            "User-Agent": "ObserverProtocol-Webhook/1.0",
        }
        if headers:
            request_headers.update(headers)

        delivery = WebhookDelivery(
            delivery_id=delivery_id,
            webhook_id=payload.webhook_id,
            event_type=payload.event_type,
            url=url,
            payload=payload_json,
            status=WebhookStatus.PENDING.value,
            created_at=datetime.utcnow().isoformat(),
        )

        if not AIOHTTP_AVAILABLE:
            delivery.status = WebhookStatus.FAILED.value
            delivery.error_message = "aiohttp not installed — webhook delivery disabled"
            self._delivery_history.append(delivery)
            return delivery

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    data=payload_json,
                    headers=request_headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    delivery.response_status = response.status
                    delivery.response_body = await response.text()
                    if 200 <= response.status < 300:
                        delivery.status = WebhookStatus.DELIVERED.value
                        delivery.delivered_at = datetime.utcnow().isoformat()
                    else:
                        delivery.status = WebhookStatus.FAILED.value
                        delivery.error_message = f"HTTP {response.status}"
        except asyncio.TimeoutError:
            delivery.status = WebhookStatus.FAILED.value
            delivery.error_message = "Request timeout"
        except Exception as exc:
            delivery.status = WebhookStatus.FAILED.value
            delivery.error_message = str(exc)

        self._delivery_history.append(delivery)
        return delivery

    async def send_with_retry(
        self,
        url: str,
        payload: WebhookPayload,
        headers: Optional[Dict[str, str]] = None,
    ) -> WebhookDelivery:
        delivery = None
        for attempt in range(self.max_retries + 1):
            delivery = await self.send_webhook(url, payload, headers)
            if delivery.status == WebhookStatus.DELIVERED.value:
                return delivery
            if attempt < self.max_retries:
                delivery.status = WebhookStatus.RETRYING.value
                delivery.retry_count = attempt + 1
                await asyncio.sleep(self.retry_delay * (2 ** attempt))
        if delivery:
            delivery.status = WebhookStatus.FAILED.value
        return delivery

    def get_delivery_history(
        self,
        webhook_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[WebhookDelivery]:
        history = self._delivery_history
        if webhook_id:
            history = [d for d in history if d.webhook_id == webhook_id]
        if event_type:
            history = [d for d in history if d.event_type == event_type]
        return history


def _get_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    return url


class WebhookRegistry:
    """Registry for managing webhook endpoints and delivering events."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or _get_db_url()
        self.deliverer = WebhookDeliverer()

    def _get_db_connection(self):
        import psycopg2
        return psycopg2.connect(self.db_url)

    def register_webhook(
        self,
        entity_id: str,
        entity_type: str,
        url: str,
        events: List[str],
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        webhook_id = str(uuid.uuid4())
        conn = self._get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO webhook_registry (
                    webhook_id, entity_id, entity_type, url,
                    events, secret, is_active, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                RETURNING webhook_id, created_at
                """,
                (webhook_id, entity_id, entity_type, url, json.dumps(events), secret, True),
            )
            result = cursor.fetchone()
            conn.commit()
            return {
                "webhook_id": result[0],
                "entity_id": entity_id,
                "entity_type": entity_type,
                "url": url,
                "events": events,
                "created_at": result[1].isoformat() if result[1] else None,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    def get_webhooks_for_event(
        self,
        event_type: str,
        entity_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        conn = self._get_db_connection()
        cursor = conn.cursor()
        try:
            query = """
                SELECT webhook_id, entity_id, entity_type, url, events, secret
                FROM webhook_registry
                WHERE is_active = TRUE AND events @> %s
            """
            params = [json.dumps([event_type])]
            if entity_id:
                query += " AND entity_id = %s"
                params.append(entity_id)
            cursor.execute(query, params)
            return [
                {
                    "webhook_id": row[0],
                    "entity_id": row[1],
                    "entity_type": row[2],
                    "url": row[3],
                    "events": json.loads(row[4]),
                    "secret": row[5],
                }
                for row in cursor.fetchall()
            ]
        finally:
            cursor.close()
            conn.close()

    async def notify_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        entity_id: Optional[str] = None,
    ) -> List[WebhookDelivery]:
        """Generic event notification. Delivers to all subscribers."""
        payload = WebhookPayload(
            event_type=event_type,
            timestamp=datetime.utcnow().isoformat(),
            data=data,
            webhook_id=str(uuid.uuid4()),
        )
        webhooks = self.get_webhooks_for_event(event_type, entity_id)
        deliveries: List[WebhookDelivery] = []
        seen_urls: set = set()
        for webhook in webhooks:
            if webhook["url"] in seen_urls:
                continue
            seen_urls.add(webhook["url"])
            if webhook.get("secret"):
                self.deliverer.signer = WebhookSigner(webhook["secret"])
            delivery = await self.deliverer.send_with_retry(
                url=webhook["url"], payload=payload
            )
            deliveries.append(delivery)
            self._record_delivery(delivery, webhook["webhook_id"])
        return deliveries

    async def notify_vac_revoked(
        self,
        credential_id: str,
        agent_id: str,
        reason: str,
        revoked_by: Optional[str] = None,
    ) -> List[WebhookDelivery]:
        data: Dict[str, Any] = {
            "credential_id": credential_id,
            "agent_id": agent_id,
            "reason": reason,
            "revoked_at": datetime.utcnow().isoformat(),
        }
        if revoked_by:
            data["revoked_by"] = revoked_by
        return await self.notify_event(
            WebhookEventType.VAC_REVOKED.value, data, entity_id=agent_id
        )

    def _record_delivery(self, delivery: WebhookDelivery, webhook_id: str) -> None:
        conn = self._get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO webhook_deliveries (
                    delivery_id, webhook_id, event_type, url,
                    payload, status, response_status, response_body,
                    error_message, retry_count, created_at, delivered_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    delivery.delivery_id, webhook_id, delivery.event_type,
                    delivery.url, delivery.payload, delivery.status,
                    delivery.response_status, delivery.response_body,
                    delivery.error_message, delivery.retry_count,
                    delivery.created_at, delivery.delivered_at,
                ),
            )
            conn.commit()
        except Exception as exc:
            conn.rollback()
            print(f"Failed to record webhook delivery: {exc}")
        finally:
            cursor.close()
            conn.close()


# ── Convenience hooks ──────────────────────────────────────────────────────────

async def on_vac_revoked(
    credential_id: str,
    agent_id: str,
    reason: str,
    revoked_by: Optional[str] = None,
) -> List[WebhookDelivery]:
    registry = WebhookRegistry()
    return await registry.notify_vac_revoked(
        credential_id=credential_id,
        agent_id=agent_id,
        reason=reason,
        revoked_by=revoked_by,
    )


async def on_vc_issued(
    credential_id: str,
    agent_did: str,
    credential_type: str,
) -> List[WebhookDelivery]:
    registry = WebhookRegistry()
    return await registry.notify_event(
        WebhookEventType.VC_ISSUED.value,
        {
            "credential_id": credential_id,
            "agent_did": agent_did,
            "credential_type": credential_type,
            "issued_at": datetime.utcnow().isoformat(),
        },
    )


async def on_vp_submitted(
    vp_id: str,
    holder_did: str,
) -> List[WebhookDelivery]:
    registry = WebhookRegistry()
    return await registry.notify_event(
        WebhookEventType.VP_SUBMITTED.value,
        {
            "vp_id": vp_id,
            "holder_did": holder_did,
            "submitted_at": datetime.utcnow().isoformat(),
        },
    )


async def on_did_registered(agent_did: str) -> List[WebhookDelivery]:
    registry = WebhookRegistry()
    return await registry.notify_event(
        WebhookEventType.DID_REGISTERED.value,
        {"agent_did": agent_did, "registered_at": datetime.utcnow().isoformat()},
    )


async def on_did_rotated(agent_did: str) -> List[WebhookDelivery]:
    registry = WebhookRegistry()
    return await registry.notify_event(
        WebhookEventType.DID_ROTATED.value,
        {"agent_did": agent_did, "rotated_at": datetime.utcnow().isoformat()},
    )
