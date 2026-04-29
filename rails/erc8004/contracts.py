"""
ERC-8004 contract addresses and ABI event definitions.

Contract addresses are deterministic across EVM chains (CREATE2 deployment).
Validation Registry is specced but not yet deployed — addresses TBD.
TRC-8004 on TRON uses M2M Registry contracts (BofAI deployment).
"""

# ── Base Mainnet (eip155:8453) ───────────────────────────────

BASE_MAINNET = {
    "chain": "base",
    "chain_id": "eip155:8453",
    "rpc_url": "https://mainnet.base.org",
    "identity_registry": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    "reputation_registry": "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    "validation_registry": None,  # Not yet deployed
}

# ── Base Sepolia (eip155:84532) ──────────────────────────────

BASE_SEPOLIA = {
    "chain": "base_sepolia",
    "chain_id": "eip155:84532",
    "rpc_url": "https://sepolia.base.org",
    "identity_registry": "0x8004A818BFB912233c491871b3d84c89A494BD9e",
    "reputation_registry": "0x8004B663056A597Dffe9eCcC1965A193B7388713",
    "validation_registry": None,
}

# ── TRON Mainnet (TRC-8004 / M2M Registry) ───────────────────
# References M2M Registry contracts (BofAI deployment).
# No AINFT SDK dependency.

TRON_MAINNET = {
    "chain": "tron",
    "chain_id": "tron:mainnet",
    "rpc_url": "https://api.trongrid.io",
    # M2M Registry contracts (BofAI deployment). No AINFT SDK dependency.
    "identity_registry": "TFLvivMdKsk6v2GrwyD2apEr9dU1w7p7Fy",
    "reputation_registry": "TFbvfLDa4eFqNR5vy24nTrhgZ74HmQ6yat",
    "validation_registry": "TLCWcW8Qmo7QMNoAKfBhGYfGpHkw1krUEm",
}

# ── Event signatures (keccak256 topic hashes) ────────────────

# Identity Registry events
EVENT_REGISTERED = "0x"  # Registered(uint256 indexed agentId, string agentURI, address indexed owner)
EVENT_URI_UPDATED = "0x"  # URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)
EVENT_METADATA_SET = "0x"  # MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey, string metadataKey, bytes metadataValue)

# Reputation Registry events
EVENT_NEW_FEEDBACK = "0x"  # NewFeedback(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, ...)
EVENT_FEEDBACK_REVOKED = "0x"  # FeedbackRevoked(uint256 indexed agentId, address indexed clientAddress, uint64 indexed feedbackIndex)
EVENT_RESPONSE_APPENDED = "0x"  # ResponseAppended(uint256 indexed agentId, address indexed clientAddress, uint64 feedbackIndex, address indexed responder, ...)

# Validation Registry events
EVENT_VALIDATION_REQUEST = "0x"  # ValidationRequest(address indexed validatorAddress, uint256 indexed agentId, string requestURI, bytes32 indexed requestHash)
EVENT_VALIDATION_RESPONSE = "0x"  # ValidationResponse(address indexed validatorAddress, uint256 indexed agentId, bytes32 indexed requestHash, ...)

# ── ABI fragments for eth_getLogs decoding ───────────────────

IDENTITY_REGISTRY_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": False, "name": "agentURI", "type": "string"},
            {"indexed": True, "name": "owner", "type": "address"},
        ],
        "name": "Registered",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": False, "name": "newURI", "type": "string"},
            {"indexed": True, "name": "updatedBy", "type": "address"},
        ],
        "name": "URIUpdated",
        "type": "event",
    },
]

REPUTATION_REGISTRY_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": True, "name": "clientAddress", "type": "address"},
            {"indexed": False, "name": "feedbackIndex", "type": "uint64"},
            {"indexed": False, "name": "value", "type": "int128"},
            {"indexed": False, "name": "valueDecimals", "type": "uint8"},
            {"indexed": True, "name": "indexedTag1", "type": "string"},
            {"indexed": False, "name": "tag1", "type": "string"},
            {"indexed": False, "name": "tag2", "type": "string"},
            {"indexed": False, "name": "endpoint", "type": "string"},
            {"indexed": False, "name": "feedbackURI", "type": "string"},
            {"indexed": False, "name": "feedbackHash", "type": "bytes32"},
        ],
        "name": "NewFeedback",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": True, "name": "clientAddress", "type": "address"},
            {"indexed": False, "name": "feedbackIndex", "type": "uint64"},
            {"indexed": True, "name": "responder", "type": "address"},
            {"indexed": False, "name": "responseURI", "type": "string"},
            {"indexed": False, "name": "responseHash", "type": "bytes32"},
        ],
        "name": "ResponseAppended",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": True, "name": "clientAddress", "type": "address"},
            {"indexed": True, "name": "feedbackIndex", "type": "uint64"},
        ],
        "name": "FeedbackRevoked",
        "type": "event",
    },
]

VALIDATION_REGISTRY_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "validatorAddress", "type": "address"},
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": False, "name": "requestURI", "type": "string"},
            {"indexed": True, "name": "requestHash", "type": "bytes32"},
        ],
        "name": "ValidationRequest",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "validatorAddress", "type": "address"},
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": True, "name": "requestHash", "type": "bytes32"},
            {"indexed": False, "name": "response", "type": "uint8"},
            {"indexed": False, "name": "responseURI", "type": "string"},
            {"indexed": False, "name": "responseHash", "type": "bytes32"},
            {"indexed": False, "name": "tag", "type": "string"},
        ],
        "name": "ValidationResponse",
        "type": "event",
    },
]

# ── Function selectors for contract calls ────────────────────

# giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)
GIVE_FEEDBACK_SELECTOR = "0x"  # Computed at runtime

# appendResponse(uint256,address,uint64,string,bytes32)
APPEND_RESPONSE_SELECTOR = "0x"

# validationResponse(bytes32,uint8,string,bytes32,string)
VALIDATION_RESPONSE_SELECTOR = "0x"


def get_chain_config(chain: str) -> dict:
    """Get contract addresses and RPC config for a chain."""
    configs = {
        "base": BASE_MAINNET,
        "base_sepolia": BASE_SEPOLIA,
        "tron": TRON_MAINNET,
    }
    return configs.get(chain, {})
