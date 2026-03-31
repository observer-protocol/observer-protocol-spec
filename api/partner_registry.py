#!/usr/bin/env python3
"""
Partner Registry Module
Observer Protocol VAC Specification v0.3

Manages partner registration, verification, and attestation issuance.
"""

import json
import hashlib
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import psycopg2
import psycopg2.extras
from crypto_verification import (
    verify_signature,
    detect_key_type,
    cache_public_key
)


def _get_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    return url


class PartnerRegistry:
    """Manages partner registration and attestations."""

    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or _get_db_url()
    
    def _get_db_connection(self):
        """Get database connection."""
        return psycopg2.connect(self.db_url)
    
    def register_partner(
        self,
        partner_name: str,
        partner_type: str,
        public_key: str,
        webhook_url: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Register a new partner in the registry.
        
        Args:
            partner_name: Unique name for the partner
            partner_type: One of 'corpo', 'verifier', 'counterparty', 'infrastructure'
            public_key: Partner's public key for attestation signing
            webhook_url: Optional webhook URL for revocation events
            metadata: Optional metadata dictionary
            
        Returns:
            Dict with partner_id and registration details
        """
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cursor.execute("""
                INSERT INTO partner_registry (
                    partner_name, partner_type, public_key, webhook_url, metadata
                ) VALUES (%s, %s, %s, %s, %s)
                RETURNING partner_id, partner_name, partner_type, registered_at
            """, (partner_name, partner_type, public_key, webhook_url, json.dumps(metadata or {})))
            
            result = cursor.fetchone()
            conn.commit()
            
            return {
                "partner_id": str(result['partner_id']),
                "partner_name": result['partner_name'],
                "partner_type": result['partner_type'],
                "registered_at": result['registered_at'].isoformat(),
                "status": "registered"
            }
            
        except psycopg2.IntegrityError as e:
            conn.rollback()
            raise ValueError(f"Partner with name '{partner_name}' already exists")
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()
    
    def get_partner(self, partner_id: str) -> Optional[Dict[str, Any]]:
        """Get partner details by ID."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cursor.execute("""
                SELECT partner_id, partner_name, partner_type, public_key,
                       webhook_url, is_active, registered_at, last_verified_at, metadata
                FROM partner_registry
                WHERE partner_id = %s
            """, (partner_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                "partner_id": str(row['partner_id']),
                "partner_name": row['partner_name'],
                "partner_type": row['partner_type'],
                "public_key": row['public_key'],
                "webhook_url": row['webhook_url'],
                "is_active": row['is_active'],
                "registered_at": row['registered_at'].isoformat(),
                "last_verified_at": row['last_verified_at'].isoformat() if row['last_verified_at'] else None,
                "metadata": row['metadata']
            }
            
        finally:
            cursor.close()
            conn.close()
    
    def list_partners(
        self,
        partner_type: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List partners with optional filtering."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            query = """
                SELECT partner_id, partner_name, partner_type, public_key,
                       is_active, registered_at
                FROM partner_registry
                WHERE 1=1
            """
            params = []
            
            if partner_type:
                query += " AND partner_type = %s"
                params.append(partner_type)
            
            if is_active is not None:
                query += " AND is_active = %s"
                params.append(is_active)
            
            query += " ORDER BY registered_at DESC"
            
            cursor.execute(query, params)
            
            return [{
                "partner_id": str(row['partner_id']),
                "partner_name": row['partner_name'],
                "partner_type": row['partner_type'],
                "public_key": row['public_key'],
                "is_active": row['is_active'],
                "registered_at": row['registered_at'].isoformat()
            } for row in cursor.fetchall()]
            
        finally:
            cursor.close()
            conn.close()
    
    def verify_partner_key(self, partner_id: str) -> bool:
        """
        Verify a partner's public key is valid.
        
        This performs basic validation on the key format.
        """
        partner = self.get_partner(partner_id)
        if not partner:
            return False
        
        public_key = partner['public_key']
        key_type = detect_key_type(public_key)
        
        if key_type == 'unknown':
            return False
        
        # Update last_verified_at
        conn = self._get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE partner_registry
                SET last_verified_at = NOW()
                WHERE partner_id = %s
            """, (partner_id,))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        
        return True
    
    def issue_attestation(
        self,
        partner_id: str,
        agent_id: str,
        claims: Dict[str, Any],
        credential_id: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        attestation_signature: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Issue a partner attestation for an agent.
        
        Args:
            partner_id: ID of the issuing partner
            agent_id: ID of the agent being attested
            claims: JSON object containing attested claims
            credential_id: Optional specific VAC credential to attach to
            expires_in_days: Optional expiration time for attestation
            attestation_signature: Partner's signature of the attestation
            
        Returns:
            Dict with attestation details
        """
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            # Verify partner exists and is active
            cursor.execute("""
                SELECT partner_id, public_key, is_active
                FROM partner_registry
                WHERE partner_id = %s
            """, (partner_id,))

            partner = cursor.fetchone()
            if not partner:
                raise ValueError(f"Partner {partner_id} not found")

            if not partner['is_active']:
                raise ValueError(f"Partner {partner_id} is not active")

            # Look up agent_did for use in the attestation payload (Layer 5)
            cursor.execute(
                "SELECT agent_did FROM observer_agents WHERE agent_id = %s",
                (agent_id,),
            )
            agent_row = cursor.fetchone()
            agent_did = agent_row['agent_did'] if agent_row and agent_row['agent_did'] else None

            # If no credential_id provided, get or create active VAC
            if not credential_id:
                cursor.execute("""
                    SELECT credential_id
                    FROM vac_credentials
                    WHERE agent_id = %s
                      AND is_revoked = FALSE
                      AND expires_at > NOW()
                    ORDER BY issued_at DESC
                    LIMIT 1
                """, (agent_id,))

                cred_row = cursor.fetchone()
                if cred_row:
                    credential_id = cred_row['credential_id']
                else:
                    # Generate new VAC (requires vac_generator)
                    from vac_generator import VACGenerator
                    generator = VACGenerator()
                    vp = generator.generate_vac(agent_id, include_extensions=False)
                    # Extract credential_id from embedded VC (strip urn:uuid: prefix for UUID column)
                    vcs = vp.get("verifiableCredential", [])
                    raw_id = vcs[0].get("id", "") if vcs else ""
                    credential_id = raw_id.removeprefix("urn:uuid:") if raw_id else None
            
            # Calculate expiration
            expires_at = None
            if expires_in_days:
                expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
            
            # Create attestation hash — include agent_did when available
            attestation_data = {
                "partner_id": partner_id,
                "agent_id": agent_id,
                "claims": claims,
                "issued_at": datetime.utcnow().isoformat(),
            }
            if agent_did:
                attestation_data["agent_did"] = agent_did
            attestation_hash = hashlib.sha256(
                json.dumps(attestation_data, sort_keys=True).encode()
            ).hexdigest()
            
            # Bug #2 Fix: Verify attestation signature cryptographically
            if not attestation_signature:
                raise ValueError("Attestation signature required")
            
            # Verify the attestation signature
            attestation_hash_bytes = bytes.fromhex(attestation_hash)
            is_valid = verify_signature(attestation_hash_bytes, attestation_signature, partner['public_key'])
            if not is_valid:
                raise ValueError("Attestation signature verification failed")
            
            # Insert attestation
            cursor.execute("""
                INSERT INTO partner_attestations (
                    credential_id, partner_id, claims,
                    attestation_signature, attestation_hash, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING attestation_id, issued_at
            """, (
                credential_id, partner_id, json.dumps(claims),
                attestation_signature, attestation_hash, expires_at
            ))
            
            result = cursor.fetchone()
            conn.commit()
            
            resp = {
                "attestation_id": str(result['attestation_id']),
                "credential_id": str(credential_id) if credential_id else None,
                "partner_id": partner_id,
                "agent_id": agent_id,
                "claims": claims,
                "issued_at": result['issued_at'].isoformat(),
                "attestation_hash": attestation_hash,
            }
            if agent_did:
                resp["agent_did"] = agent_did
            if expires_at:
                resp["expires_at"] = expires_at.isoformat()
            return resp
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()
    
    def get_attestations_for_agent(
        self,
        agent_id: str,
        partner_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all attestations for an agent."""
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            query = """
                SELECT
                    pa.attestation_id,
                    pa.credential_id,
                    pa.claims,
                    pa.issued_at,
                    pa.expires_at,
                    pa.attestation_hash,
                    pr.partner_id,
                    pr.partner_name,
                    pr.partner_type,
                    oa.agent_did
                FROM partner_attestations pa
                JOIN vac_credentials vc ON vc.credential_id = pa.credential_id
                JOIN partner_registry pr ON pr.partner_id = pa.partner_id
                LEFT JOIN observer_agents oa ON oa.agent_id = vc.agent_id
                WHERE vc.agent_id = %s
                  AND vc.is_revoked = FALSE
            """
            params = [agent_id]
            
            if partner_type:
                query += " AND pr.partner_type = %s"
                params.append(partner_type)
            
            query += " ORDER BY pa.issued_at DESC"
            
            cursor.execute(query, params)
            
            rows = cursor.fetchall()
            result_list = []
            for row in rows:
                entry: Dict[str, Any] = {
                    "attestation_id": str(row['attestation_id']),
                    "credential_id": str(row['credential_id']) if row['credential_id'] else None,
                    "partner_id": str(row['partner_id']),
                    "partner_name": row['partner_name'],
                    "partner_type": row['partner_type'],
                    "claims": row['claims'],
                    "issued_at": row['issued_at'].isoformat(),
                    "attestation_hash": row['attestation_hash'],
                }
                if row['agent_did']:
                    entry["agent_did"] = row['agent_did']
                if row['expires_at']:
                    entry["expires_at"] = row['expires_at'].isoformat()
                result_list.append(entry)
            return result_list
            
        finally:
            cursor.close()
            conn.close()
    
    def add_counterparty_metadata(
        self,
        credential_id: str,
        counterparty_id: str,
        metadata: Dict[str, Any],
        ipfs_cid: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Add counterparty metadata hash to a VAC credential.
        
        Args:
            credential_id: The VAC credential ID
            counterparty_id: Hashed counterparty identifier
            metadata: The metadata (will be hashed, not stored directly)
            ipfs_cid: Optional IPFS CID for off-chain metadata storage
            
        Returns:
            Dict with metadata hash details
        """
        # Hash the metadata
        metadata_hash = hashlib.sha256(
            json.dumps(metadata, sort_keys=True).encode()
        ).hexdigest()
        
        conn = self._get_db_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cursor.execute("""
                INSERT INTO counterparty_metadata (
                    credential_id, counterparty_id, metadata_hash, ipfs_cid
                ) VALUES (%s, %s, %s, %s)
                RETURNING metadata_id, created_at
            """, (credential_id, counterparty_id, metadata_hash, ipfs_cid))
            
            result = cursor.fetchone()
            conn.commit()
            
            return {
                "metadata_id": str(result['metadata_id']),
                "credential_id": credential_id,
                "counterparty_id": counterparty_id,
                "metadata_hash": metadata_hash,
                "ipfs_cid": ipfs_cid,
                "created_at": result['created_at'].isoformat()
            }
            
        except psycopg2.IntegrityError:
            conn.rollback()
            # Update existing
            cursor.execute("""
                UPDATE counterparty_metadata
                SET metadata_hash = %s, ipfs_cid = %s
                WHERE credential_id = %s AND counterparty_id = %s
                RETURNING metadata_id, created_at
            """, (metadata_hash, ipfs_cid, credential_id, counterparty_id))
            
            result = cursor.fetchone()
            conn.commit()
            
            return {
                "metadata_id": str(result['metadata_id']),
                "credential_id": credential_id,
                "counterparty_id": counterparty_id,
                "metadata_hash": metadata_hash,
                "ipfs_cid": ipfs_cid,
                "created_at": result['created_at'].isoformat(),
                "updated": True
            }
        finally:
            cursor.close()
            conn.close()
    
    def deactivate_partner(self, partner_id: str) -> bool:
        """Deactivate a partner."""
        conn = self._get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE partner_registry
                SET is_active = FALSE
                WHERE partner_id = %s
            """, (partner_id,))
            
            conn.commit()
            return cursor.rowcount > 0
        finally:
            cursor.close()
            conn.close()


# Convenience functions for Corpo integration
def register_corpo_partner(
    legal_entity_name: str,
    public_key: str,
    webhook_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Register a Corpo legal wrapper partner.
    
    This is a convenience function for registering Corpo partners
    which handle legal_entity_id attestations.
    """
    registry = PartnerRegistry()
    return registry.register_partner(
        partner_name=legal_entity_name,
        partner_type='corpo',
        public_key=public_key,
        webhook_url=webhook_url,
        metadata={"service": "legal_entity_verification"}
    )


def issue_corpo_attestation(
    partner_id: str,
    agent_id: str,
    legal_entity_id: str,
    attestation_signature: Optional[str] = None,
    jurisdiction: Optional[str] = None,
    compliance_status: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Issue a Corpo legal entity attestation.

    Attaches legal_entity_id to the agent's VAC via partner attestations.
    Per v0.3 spec, legal_entity_id is moved from agent table to extensions.

    Bug fix: attestation_signature was previously swallowed into **additional_claims
    and never forwarded to registry.issue_attestation(), causing every call to fail
    with "Attestation signature required".
    """
    registry = PartnerRegistry()

    claims: Dict[str, Any] = {"legal_entity_id": legal_entity_id}
    if jurisdiction:
        claims["jurisdiction"] = jurisdiction
    if compliance_status:
        claims["compliance_status"] = compliance_status

    return registry.issue_attestation(
        partner_id=partner_id,
        agent_id=agent_id,
        claims=claims,
        attestation_signature=attestation_signature,
    )


if __name__ == "__main__":
    # Test functions
    registry = PartnerRegistry()
    
    # List all partners
    partners = registry.list_partners()
    print(f"Registered partners: {len(partners)}")
    for p in partners:
        print(f"  - {p['partner_name']} ({p['partner_type']})")
