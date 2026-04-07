#!/usr/bin/env python3
"""
AIP Manager — Business logic for AIP operations
"""

import json
from datetime import datetime, timedelta, timezone

# Fix for Python 3.9 compatibility - use datetime.now(timezone.utc) instead of datetime.utcnow()
from typing import Optional, List, Dict, Any, Tuple
import psycopg2
import psycopg2.extras
import uuid

from aip_core import (
    DB_URL, KYBVerifiableCredential, DelegationCredential, DelegationScope,
    DelegationSignature, RevocationRecord, TypeRegistryValidator, DIDResolver,
    RemediationResponseEnvelope, RemediationOptionEnvelope,
    AIPError, TypeRegistryError, CredentialValidationError, DIDResolutionError
)


class DelegationChainVerifier:
    """
    EAGER delegation chain verification per Section 9.3.
    Verifies FULL chain at query time, regardless of depth.
    No lazy evaluation permitted.
    """
    
    def __init__(self, aip_manager: 'AIPManager'):
        self.aip_manager = aip_manager
    
    def verify_chain(
        self,
        credential_id: str,
        agent_did: str,
        expected_org_did: Optional[str] = None
    ) -> Tuple[bool, str, List[DelegationCredential]]:
        """Verify the full delegation chain from credential to root"""
        chain = []
        current_cred_id = credential_id
        visited = set()
        
        while current_cred_id:
            if current_cred_id in visited:
                return False, "Circular delegation chain detected", chain
            visited.add(current_cred_id)
            
            cred = self.aip_manager.get_delegation_credential(current_cred_id)
            if not cred:
                return False, f"Missing credential in chain: {current_cred_id}", chain
            
            if cred.status == 'revoked':
                return False, f"Revoked credential in chain: {current_cred_id}", chain
            
            if cred.status == 'expired':
                return False, f"Expired credential in chain: {current_cred_id}", chain
            
            expires = datetime.fromisoformat(cred.expires_at.replace('Z', '+00:00'))
            if expires < datetime.now(expires.tzinfo):
                return False, f"Expired credential in chain: {current_cred_id}", chain
            
            if not cred.agent_did.startswith('did:web:'):
                return False, f"Non-did:web agent DID in chain: {cred.agent_did}", chain
            
            if not cred.org_did.startswith('did:web:'):
                return False, f"Non-did:web org DID in chain: {cred.org_did}", chain
            
            if cred.delegation_depth > 1:
                agent_domain = DIDResolver.extract_domain(cred.agent_did)
                org_domain = DIDResolver.extract_domain(cred.org_did)
                if agent_domain != org_domain:
                    return False, f"Domain mismatch: {agent_domain} vs {org_domain}", chain
            
            if cred.delegation_depth > cred.max_delegation_depth:
                return False, f"Depth exceeded: {cred.delegation_depth} > {cred.max_delegation_depth}", chain
            
            chain.append(cred)
            current_cred_id = cred.parent_credential_id
        
        for i, cred in enumerate(chain):
            if i < len(chain) - 1:
                parent = chain[i + 1]
                if cred.org_did != parent.agent_did:
                    return False, f"Chain link mismatch: {cred.org_did} != {parent.agent_did}", chain
        
        if expected_org_did and chain:
            root_cred = chain[-1]
            if root_cred.org_did != expected_org_did:
                return False, f"Root org mismatch: {root_cred.org_did} != {expected_org_did}", chain
        
        return True, "Chain verified", chain


class AIPManager:
    """Main manager for AIP operations"""
    
    def __init__(self, db_url: str = DB_URL):
        self.db_url = db_url
        self.type_registry = TypeRegistryValidator(db_url)
        self.did_resolver = DIDResolver()
        self.chain_verifier = DelegationChainVerifier(self)
    
    def _get_connection(self):
        return psycopg2.connect(self.db_url)
    
    def issue_kyb_vc(
        self,
        org_did: str,
        kyb_provider: str,
        kyb_result: str,
        issuer_did: str = "did:web:agenticterminal.io",
        issuer_type: str = "at_anchored",
        kyb_provider_did: Optional[str] = None,
        kyb_scope: str = "organization",
        expiration_days: int = 365
    ) -> KYBVerifiableCredential:
        """Issue a new KYB Verifiable Credential"""
        if not org_did.startswith('did:web:'):
            raise DIDResolutionError(f"Organization DID must be did:web, got: {org_did}")
        
        credential_id = str(uuid.uuid4())
        issuance_date = datetime.utcnow()
        expiration_date = issuance_date + timedelta(days=expiration_days)
        kyb_completed_at = datetime.utcnow()
        
        credential_json = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://observerprotocol.org/contexts/kyb/v1"
            ],
            "type": ["VerifiableCredential", "KYBAttestation"],
            "id": f"https://agenticterminal.io/credentials/kyb/{credential_id}",
            "issuer": issuer_did,
            "issuanceDate": issuance_date.isoformat() + "Z",
            "expirationDate": expiration_date.isoformat() + "Z",
            "credentialSubject": {
                "id": org_did,
                "type": "Organization",
                "kybProvider": kyb_provider,
                "kybProviderDid": kyb_provider_did,
                "kybResult": kyb_result,
                "kybCompletedAt": kyb_completed_at.isoformat() + "Z",
                "kybScope": kyb_scope
            }
        }
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO kyb_verifiable_credentials (
                    credential_id, credential_json, issuer_did, issuer_type,
                    org_did, kyb_provider, kyb_provider_did, kyb_result,
                    kyb_completed_at, kyb_scope, issuance_date, expiration_date,
                    status, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                credential_id, json.dumps(credential_json), issuer_did, issuer_type,
                org_did, kyb_provider, kyb_provider_did, kyb_result,
                kyb_completed_at, kyb_scope, issuance_date, expiration_date, "active"
            ))
            conn.commit()
            
            return KYBVerifiableCredential(
                credential_id=credential_id,
                issuer_did=issuer_did,
                issuer_type=issuer_type,
                org_did=org_did,
                kyb_provider=kyb_provider,
                kyb_provider_did=kyb_provider_did,
                kyb_result=kyb_result,
                kyb_completed_at=kyb_completed_at.isoformat(),
                kyb_scope=kyb_scope,
                issuance_date=issuance_date.isoformat(),
                expiration_date=expiration_date.isoformat(),
                credential_json=credential_json
            )
        finally:
            cursor.close()
            conn.close()
    
    def get_kyb_vc(self, credential_id: str) -> Optional[KYBVerifiableCredential]:
        """Retrieve a KYB VC by ID"""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM kyb_verifiable_credentials WHERE credential_id = %s", (credential_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            return KYBVerifiableCredential(
                credential_id=row['credential_id'],
                issuer_did=row['issuer_did'],
                issuer_type=row['issuer_type'],
                org_did=row['org_did'],
                kyb_provider=row['kyb_provider'],
                kyb_provider_did=row['kyb_provider_did'],
                kyb_result=row['kyb_result'],
                kyb_completed_at=row['kyb_completed_at'].isoformat() if row['kyb_completed_at'] else None,
                kyb_scope=row['kyb_scope'],
                issuance_date=row['issuance_date'].isoformat(),
                expiration_date=row['expiration_date'].isoformat() if row['expiration_date'] else None,
                credential_json=row['credential_json'],
                status=row['status']
            )
        finally:
            cursor.close()
            conn.close()
    
    def get_org_kyb_vcs(self, org_did: str, active_only: bool = True) -> List[KYBVerifiableCredential]:
        """Get all KYB VCs for an organization"""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            query = "SELECT * FROM kyb_verifiable_credentials WHERE org_did = %s"
            if active_only:
                query += " AND status = 'active'"
            query += " ORDER BY issuance_date DESC"
            
            cursor.execute(query, (org_did,))
            rows = cursor.fetchall()
            
            return [KYBVerifiableCredential(
                credential_id=row['credential_id'],
                issuer_did=row['issuer_did'],
                issuer_type=row['issuer_type'],
                org_did=row['org_did'],
                kyb_provider=row['kyb_provider'],
                kyb_provider_did=row['kyb_provider_did'],
                kyb_result=row['kyb_result'],
                kyb_completed_at=row['kyb_completed_at'].isoformat() if row['kyb_completed_at'] else None,
                kyb_scope=row['kyb_scope'],
                issuance_date=row['issuance_date'].isoformat(),
                expiration_date=row['expiration_date'].isoformat() if row['expiration_date'] else None,
                credential_json=row['credential_json'],
                status=row['status']
            ) for row in rows]
        finally:
            cursor.close()
            conn.close()
    
    def issue_delegation_credential(
        self,
        org_did: str,
        org_name: str,
        kyb_credential_id: Optional[str],
        agent_did: str,
        agent_label: Optional[str],
        scope: DelegationScope,
        delegation_depth: int = 1,
        max_delegation_depth: int = 3,
        parent_credential_id: Optional[str] = None,
        signature: Optional[DelegationSignature] = None,
        expiration_days: int = 180
    ) -> DelegationCredential:
        """Issue a new Delegation Credential"""
        if not agent_did.startswith('did:web:'):
            raise DIDResolutionError(f"Agent DID must be did:web, got: {agent_did}")
        
        if not org_did.startswith('did:web:'):
            raise DIDResolutionError(f"Org DID must be did:web, got: {org_did}")
        
        if scope.allowed_counterparty_types:
            is_valid, invalid = self.type_registry.validate_counterparty_types_list(
                scope.allowed_counterparty_types
            )
            if not is_valid:
                raise TypeRegistryError(f"Invalid counterparty types: {', '.join(invalid)}")
        
        if delegation_depth > max_delegation_depth:
            raise CredentialValidationError(
                f"delegation_depth ({delegation_depth}) exceeds max ({max_delegation_depth})"
            )
        
        credential_id = f"aip-cred-{uuid.uuid4()}"
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(days=expiration_days)
        
        if signature is None:
            signature = DelegationSignature(
                signed_by=f"{org_did}#master-key",
                algorithm="Ed25519",
                value="PENDING_SIGNATURE"
            )
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO delegation_credentials (
                    credential_id, version, org_did, org_name, kyb_credential_id,
                    agent_did, agent_label, scope_payment_settlement,
                    scope_max_transaction_value_usd, scope_allowed_counterparty_types,
                    scope_allowed_rails, scope_geographic_restriction,
                    delegation_depth, max_delegation_depth, parent_credential_id,
                    signed_by, signature_algorithm, signature_value,
                    issued_at, expires_at, status, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                credential_id, "0.3", org_did, org_name, kyb_credential_id,
                agent_did, agent_label, scope.payment_settlement,
                scope.max_transaction_value_usd, scope.allowed_counterparty_types,
                scope.allowed_rails, scope.geographic_restriction,
                delegation_depth, max_delegation_depth, parent_credential_id,
                signature.signed_by, signature.algorithm, signature.value,
                issued_at, expires_at, "active"
            ))
            conn.commit()
            
            return DelegationCredential(
                credential_id=credential_id,
                version="0.3",
                org_did=org_did,
                org_name=org_name,
                kyb_credential_id=kyb_credential_id,
                agent_did=agent_did,
                agent_label=agent_label,
                scope=scope,
                delegation_depth=delegation_depth,
                max_delegation_depth=max_delegation_depth,
                parent_credential_id=parent_credential_id,
                signature=signature,
                issued_at=issued_at.isoformat(),
                expires_at=expires_at.isoformat()
            )
        finally:
            cursor.close()
            conn.close()
    
    def get_delegation_credential(self, credential_id: str) -> Optional[DelegationCredential]:
        """Retrieve a Delegation Credential by ID"""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            cursor.execute("SELECT * FROM delegation_credentials WHERE credential_id = %s", (credential_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            scope = DelegationScope(
                payment_settlement=row['scope_payment_settlement'],
                max_transaction_value_usd=float(row['scope_max_transaction_value_usd']) if row['scope_max_transaction_value_usd'] else None,
                allowed_counterparty_types=row['scope_allowed_counterparty_types'] or [],
                allowed_rails=row['scope_allowed_rails'] or [],
                geographic_restriction=row['scope_geographic_restriction']
            )
            
            signature = DelegationSignature(
                signed_by=row['signed_by'],
                algorithm=row['signature_algorithm'],
                value=row['signature_value']
            )
            
            return DelegationCredential(
                credential_id=row['credential_id'],
                version=row['version'],
                org_did=row['org_did'],
                org_name=row['org_name'],
                kyb_credential_id=row['kyb_credential_id'],
                agent_did=row['agent_did'],
                agent_label=row['agent_label'],
                scope=scope,
                delegation_depth=row['delegation_depth'],
                max_delegation_depth=row['max_delegation_depth'],
                parent_credential_id=row['parent_credential_id'],
                signature=signature,
                issued_at=row['issued_at'].isoformat(),
                expires_at=row['expires_at'].isoformat(),
                status=row['status']
            )
        finally:
            cursor.close()
            conn.close()
    
    def get_agent_delegation_credentials(
        self,
        agent_did: str,
        active_only: bool = True
    ) -> List[DelegationCredential]:
        """Get all delegation credentials for an agent"""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            query = "SELECT * FROM delegation_credentials WHERE agent_did = %s"
            if active_only:
                query += " AND status = 'active' AND expires_at > NOW()"
            query += " ORDER BY issued_at DESC"
            
            cursor.execute(query, (agent_did,))
            rows = cursor.fetchall()
            
            credentials = []
            for row in rows:
                scope = DelegationScope(
                    payment_settlement=row['scope_payment_settlement'],
                    max_transaction_value_usd=float(row['scope_max_transaction_value_usd']) if row['scope_max_transaction_value_usd'] else None,
                    allowed_counterparty_types=row['scope_allowed_counterparty_types'] or [],
                    allowed_rails=row['scope_allowed_rails'] or [],
                    geographic_restriction=row['scope_geographic_restriction']
                )
                
                signature = DelegationSignature(
                    signed_by=row['signed_by'],
                    algorithm=row['signature_algorithm'],
                    value=row['signature_value']
                )
                
                credentials.append(DelegationCredential(
                    credential_id=row['credential_id'],
                    version=row['version'],
                    org_did=row['org_did'],
                    org_name=row['org_name'],
                    kyb_credential_id=row['kyb_credential_id'],
                    agent_did=row['agent_did'],
                    agent_label=row['agent_label'],
                    scope=scope,
                    delegation_depth=row['delegation_depth'],
                    max_delegation_depth=row['max_delegation_depth'],
                    parent_credential_id=row['parent_credential_id'],
                    signature=signature,
                    issued_at=row['issued_at'].isoformat(),
                    expires_at=row['expires_at'].isoformat(),
                    status=row['status']
                ))
            
            return credentials
        finally:
            cursor.close()
            conn.close()
    
    def revoke_credential(
        self,
        credential_id: str,
        credential_type: str,
        revoked_by_did: str,
        revoked_by_key_id: str,
        reason: str,
        revocation_signature: str,
        reason_description: Optional[str] = None,
        cascade_to_children: bool = False
    ) -> RevocationRecord:
        """Revoke a credential"""
        if not self.type_registry.validate_revocation_reason(reason):
            valid_reasons = self.type_registry.get_valid_values('revocation_reason')
            raise TypeRegistryError(f"Invalid revocation reason: {reason}. Valid: {', '.join(valid_reasons)}")
        
        revoked_at = datetime.utcnow()
        cascaded_ids = []
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO credential_revocations (
                    credential_id, credential_type, revoked_by_did, revoked_by_key_id,
                    reason, reason_description, revocation_signature,
                    cascade_to_children, cascaded_credential_ids, revoked_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                credential_id, credential_type, revoked_by_did, revoked_by_key_id,
                reason, reason_description, revocation_signature,
                cascade_to_children, cascaded_ids, revoked_at
            ))
            
            if credential_type == 'delegation':
                cursor.execute("""
                    UPDATE delegation_credentials
                    SET status = 'revoked', updated_at = NOW()
                    WHERE credential_id = %s
                """, (credential_id,))
                
                if cascade_to_children:
                    cursor.execute("""
                        UPDATE delegation_credentials
                        SET status = 'revoked', updated_at = NOW()
                        WHERE parent_credential_id = %s
                        RETURNING credential_id
                    """, (credential_id,))
                    
                    cascaded = cursor.fetchall()
                    cascaded_ids = [row[0] for row in cascaded]
                    
                    for child_id in cascaded_ids:
                        cursor.execute("""
                            INSERT INTO credential_revocations (
                                credential_id, credential_type, revoked_by_did, revoked_by_key_id,
                                reason, reason_description, revocation_signature,
                                cascade_to_children, cascaded_credential_ids, revoked_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            child_id, credential_type, revoked_by_did, revoked_by_key_id,
                            reason, f"Cascaded from parent: {credential_id}",
                            revocation_signature, False, [], revoked_at
                        ))
                        
            elif credential_type == 'kyb_vc':
                cursor.execute("""
                    UPDATE kyb_verifiable_credentials
                    SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
                    WHERE credential_id = %s
                """, (credential_id,))
            
            conn.commit()
            
            return RevocationRecord(
                credential_id=credential_id,
                credential_type=credential_type,
                revoked_by_did=revoked_by_did,
                revoked_by_key_id=revoked_by_key_id,
                reason=reason,
                reason_description=reason_description,
                revocation_signature=revocation_signature,
                cascade_to_children=cascade_to_children,
                cascaded_credential_ids=cascaded_ids,
                revoked_at=revoked_at.isoformat()
            )
        finally:
            cursor.close()
            conn.close()
    
    def check_credential_status(self, credential_id: str) -> Dict[str, Any]:
        """Check the status of any credential"""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        try:
            # Check delegation credentials
            cursor.execute("""
                SELECT credential_id, status, expires_at, 'delegation' as cred_type
                FROM delegation_credentials
                WHERE credential_id = %s
            """, (credential_id,))
            
            row = cursor.fetchone()
            if row:
                now = datetime.now(timezone.utc)
                expires = row['expires_at']
                is_expired = expires < now if expires else False
                effective_status = 'expired' if is_expired and row['status'] == 'active' else row['status']
                
                return {
                    "credential_id": credential_id,
                    "credential_type": "delegation",
                    "status": effective_status,
                    "checked_at": datetime.utcnow().isoformat()
                }
            
            # Check KYB VCs
            cursor.execute("""
                SELECT credential_id, status, expiration_date, 'kyb_vc' as cred_type
                FROM kyb_verifiable_credentials
                WHERE credential_id = %s
            """, (credential_id,))
            
            row = cursor.fetchone()
            if row:
                now = datetime.now(timezone.utc)
                expires = row['expiration_date']
                is_expired = expires < now if expires else False
                effective_status = 'expired' if is_expired and row['status'] == 'active' else row['status']
                
                return {
                    "credential_id": credential_id,
                    "credential_type": "kyb_vc",
                    "status": effective_status,
                    "checked_at": datetime.utcnow().isoformat()
                }
            
            return {
                "credential_id": credential_id,
                "status": "not_found",
                "checked_at": datetime.utcnow().isoformat()
            }
        finally:
            cursor.close()
            conn.close()
    
    def build_remediation_envelope(
        self,
        reason: str,
        score: int,
        threshold: int,
        options: List[RemediationOptionEnvelope] = None
    ) -> RemediationResponseEnvelope:
        """
        Build a MINIMAL remediation response envelope per Section 9.1.
        AT populates option content; AIP just provides the envelope structure.
        """
        if options is None:
            options = []
        
        return RemediationResponseEnvelope(
            status="denied",
            reason=reason,
            score=score,
            threshold=threshold,
            gap=threshold - score if threshold > score else 0,
            options=options
        )
    
    def get_agent_credentials_summary(self, agent_did: str) -> Dict[str, Any]:
        """Get full credential summary for an agent (for Credential Viewer)"""
        delegation_creds = self.get_agent_delegation_credentials(agent_did, active_only=False)
        
        return {
            "agent_did": agent_did,
            "delegation_credentials": [
                {
                    "credential_id": c.credential_id,
                    "org_did": c.org_did,
                    "org_name": c.org_name,
                    "scope": c.scope.to_dict(),
                    "delegation_depth": c.delegation_depth,
                    "issued_at": c.issued_at,
                    "expires_at": c.expires_at,
                    "status": c.status
                }
                for c in delegation_creds
            ],
            "credential_count": len(delegation_creds),
            "checked_at": datetime.utcnow().isoformat()
        }
