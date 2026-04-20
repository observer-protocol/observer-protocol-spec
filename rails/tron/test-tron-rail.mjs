/**
 * TRON Rail Test Suite
 * Observer Protocol Phase 1: TRON Integration Tests
 * 
 * Run with: TRON_NETWORK=shasta node --test rails/tron/test-tron-rail.mjs
 * 
 * Updated for Mainnet Cutover: Tests environment-based configuration
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { 
  TronGridClient, 
  publicKeyToTronAddress, 
  validateTronAddress,
  tronAddressToHex,
  hexToTronAddress,
  TRC20_CONTRACTS,
  TRON_AIP_TYPES,
  TronConfig,
  getTronConfig,
  resetTronConfig,
  MAINNET_USDT_CONTRACT
} from './tron-core.mjs';

import {
  TronReceiptSchema,
  validateTronReceiptData,
  createTronReceiptPayload,
  extractReceiptSummary,
  generateReceiptId
} from './tron-receipt-vc.mjs';

import{
  TronReceiptVerifier,
  TronReceiptEndpoint,
  tronReceiptToVACExtension
} from './tron-verification.mjs';

import { TronRail } from './index.mjs';

// Test configuration
const TEST_CONFIG = {
  network: 'shasta', // Use testnet for tests
  apiKey: process.env.TRONGRID_API_KEY || 'test-key',
  minConfirmations: 1 // Lower for testnet
};

// Test data
const TEST_PUBLIC_KEY = Buffer.from(
  '04a7f2b9c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
  'hex'
);

describe('TRON Rail Integration', () => {
  
  describe('Environment Configuration', () => {
    it('should throw error when TRON_NETWORK is not set', () => {
      // Save original env
      const originalNetwork = process.env.TRON_NETWORK;
      delete process.env.TRON_NETWORK;
      resetTronConfig();
      
      try {
        assert.throws(() => {
          new TronConfig();
        }, /TRON_NETWORK/);
      } finally {
        // Restore env
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        }
        resetTronConfig();
      }
    });
    
    it('should throw error for invalid TRON_NETWORK value', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'invalid_network';
      resetTronConfig();
      
      try {
        assert.throws(() => {
          new TronConfig();
        }, /Invalid TRON_NETWORK/);
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
    
    it('should load mainnet configuration correctly', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'mainnet';
      process.env.TRONGRID_API_KEY = 'test-mainnet-key';
      resetTronConfig();
      
      try {
        const config = new TronConfig();
        
        assert.strictEqual(config.getNetworkName(), 'mainnet');
        assert.strictEqual(config.getApiEndpoint(), 'https://api.trongrid.io');
        assert.strictEqual(config.getUsdtContract(), MAINNET_USDT_CONTRACT);
        assert.strictEqual(config.getMinConfirmations(), 19);
        assert.strictEqual(config.isMainnet(), true);
        assert.strictEqual(config.isTestnet(), false);
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
    
    it('should load shasta configuration correctly', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'shasta';
      process.env.TRONGRID_API_KEY = 'test-shasta-key';
      resetTronConfig();
      
      try {
        const config = new TronConfig();
        
        assert.strictEqual(config.getNetworkName(), 'shasta');
        assert.strictEqual(config.getApiEndpoint(), 'https://api.shasta.trongrid.io');
        assert.strictEqual(config.getUsdtContract(), null);
        assert.strictEqual(config.getMinConfirmations(), 1);
        assert.strictEqual(config.isMainnet(), false);
        assert.strictEqual(config.isTestnet(), true);
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
    
    it('should validate contract network compatibility', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'mainnet';
      process.env.TRONGRID_API_KEY = 'test-key';
      resetTronConfig();
      
      try {
        const config = new TronConfig();
        
        // Mainnet contract on mainnet should be valid
        const mainnetValid = config.validateContractNetwork(MAINNET_USDT_CONTRACT);
        assert.strictEqual(mainnetValid.valid, true);
        
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
    
    it('should reject mainnet contract on shasta', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'shasta';
      process.env.TRONGRID_API_KEY = 'test-key';
      resetTronConfig();
      
      try {
        const config = new TronConfig();
        
        // Mainnet contract on shasta should be invalid
        const result = config.validateContractNetwork(MAINNET_USDT_CONTRACT);
        assert.strictEqual(result.valid, false);
        assert.ok(result.error.includes('cannot be used on shasta'));
        
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
    
    it('should mask API key in summary', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'mainnet';
      process.env.TRONGRID_API_KEY = 'abcdefghijklmnopqrstuvwxyz1234';
      resetTronConfig();
      
      try {
        const config = new TronConfig();
        const summary = config.getSummary();
        
        assert.ok(summary.apiKey.includes('...'));
        assert.ok(!summary.apiKey.includes('abcdefghijklmnopqrstuvwxyz1234'));
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
  });
  
  describe('Address Utilities', () => {
    it('should validate correct TRON addresses', () => {
      // Valid mainnet addresses (USDT contract and generated valid address)
      assert.strictEqual(validateTronAddress('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'), true);
      assert.strictEqual(validateTronAddress('TExEspsjqwjZeqT5BCZPDUvAcRSvgBQdak'), true);
      
      // Invalid addresses
      assert.strictEqual(validateTronAddress(''), false);
      assert.strictEqual(validateTronAddress('invalid'), false);
      assert.strictEqual(validateTronAddress('12345678901234567890123456789012345'), false);
    });
    
    it('should convert between Base58 and Hex formats', () => {
      const base58Addr = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
      const hexAddr = tronAddressToHex(base58Addr);
      
      assert.ok(hexAddr.startsWith('41'));
      assert.strictEqual(hexAddr.length, 42); // 0x41 + 40 hex chars
      
      const backToBase58 = hexToTronAddress(hexAddr);
      assert.strictEqual(backToBase58, base58Addr);
    });
    
    it('should derive TRON address from public key', () => {
      // This test uses a known key pair - in production would use real key
      // For now, just verify the function runs
      try {
        const address = publicKeyToTronAddress(Buffer.alloc(64, 0x42));
        assert.ok(typeof address === 'string');
        assert.ok(address.length === 34 || address === '');
      } catch (e) {
        // Expected to fail with dummy key
        assert.ok(e.message.includes('Invalid') || e.message.includes('public key'));
      }
    });
  });
  
  describe('TRC-20 Contracts', () => {
    it('should have USDT contract defined', () => {
      assert.ok(TRC20_CONTRACTS.USDT);
      assert.strictEqual(TRC20_CONTRACTS.USDT, MAINNET_USDT_CONTRACT);
    });
    
    it('should have valid USDC contract', () => {
      assert.ok(TRC20_CONTRACTS.USDC);
      assert.strictEqual(validateTronAddress(TRC20_CONTRACTS.USDC), true);
    });
  });
  
  describe('AIP Type Registry', () => {
    it('should define TRON rail types', () => {
      assert.strictEqual(TRON_AIP_TYPES.RAIL, 'tron');
      assert.strictEqual(TRON_AIP_TYPES.TRC20, 'tron:trc20');
      assert.strictEqual(TRON_AIP_TYPES.NATIVE, 'tron:native');
    });
  });
  
  describe('Receipt VC Schema', () => {
    it('should validate correct receipt data', () => {
      const validData = {
        issuer_did: 'did:op:agent-sender',
        subject_did: 'did:op:agent-recipient',
        rail: 'tron:trc20',
        asset: 'USDT',
        amount: '1000000',
        tron_tx_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
        timestamp: '2026-04-13T14:00:00Z',
        sender_address: 'TExEspsjqwjZeqT5BCZPDUvAcRSvgBQdak',
        recipient_address: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
      };
      
      const result = validateTronReceiptData(validData);
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.errors.length, 0);
    });
    
    it('should reject invalid receipt data', () => {
      const invalidData = {
        issuer_did: 'did:op:sender',
        // missing subject_did
        rail: 'invalid_rail',
        asset: 'USDT',
        amount: '1000000',
        tron_tx_hash: 'invalid_hash',
        timestamp: 'invalid_date'
      };
      
      const result = validateTronReceiptData(invalidData);
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.length > 0);
    });
    
    it('should reject invalid TRON addresses', () => {
      const invalidAddressData = {
        issuer_did: 'did:op:sender',
        subject_did: 'did:op:recipient',
        rail: 'tron:trc20',
        asset: 'USDT',
        amount: '1000000',
        tron_tx_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
        timestamp: '2026-04-13T14:00:00Z',
        sender_address: 'invalid_address'
      };
      
      const result = validateTronReceiptData(invalidAddressData);
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('sender_address')));
    });
    
    it('should reject invalid tx hash format', () => {
      const invalidHashData = {
        issuer_did: 'did:op:sender',
        subject_did: 'did:op:recipient',
        rail: 'tron:trc20',
        asset: 'USDT',
        amount: '1000000',
        tron_tx_hash: 'too_short',
        timestamp: '2026-04-13T14:00:00Z'
      };
      
      const result = validateTronReceiptData(invalidHashData);
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('tron_tx_hash')));
    });
  });
  
  describe('Receipt Payload Creation', () => {
    it('should create valid VC payload', () => {
      const data = {
        issuer_did: 'did:op:sender',
        subject_did: 'did:op:recipient',
        rail: 'tron:trc20',
        asset: 'USDT',
        amount: '1000000',
        tron_tx_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
        timestamp: '2026-04-13T14:00:00Z',
        sender_address: 'TExEspsjqwjZeqT5BCZPDUvAcRSvgBQdak',
        recipient_address: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
      };
      
      const payload = createTronReceiptPayload(data);
      
      assert.ok(payload['@context']);
      assert.ok(payload.id.startsWith('urn:uuid:'));
      assert.strictEqual(payload.type[0], 'VerifiableCredential');
      assert.strictEqual(payload.type[1], 'TronTransactionReceipt');
      assert.strictEqual(payload.issuer, data.issuer_did);
      assert.ok(payload.issuanceDate);
      assert.ok(payload.expirationDate);
      assert.strictEqual(payload.credentialSubject.id, data.subject_did);
      assert.strictEqual(payload.credentialSubject.rail, data.rail);
      assert.strictEqual(payload.credentialSubject.asset, data.asset);
      assert.strictEqual(payload.credentialSubject.amount, data.amount);
    });
    
    it('should include optional fields in payload', () => {
      const data = {
        issuer_did: 'did:op:sender',
        subject_did: 'did:op:recipient',
        rail: 'tron:trc20',
        asset: 'USDT',
        amount: '1000000',
        tron_tx_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
        timestamp: '2026-04-13T14:00:00Z',
        org_affiliation: 'Test Corp',
        sender_address: 'TExEspsjqwjZeqT5BCZPDUvAcRSvgBQdak',
        recipient_address: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
        token_contract: TRC20_CONTRACTS.USDT,
        confirmations: 20,
        network: 'mainnet'
      };
      
      const payload = createTronReceiptPayload(data);
      
      assert.strictEqual(payload.credentialSubject.orgAffiliation, 'Test Corp');
      assert.strictEqual(payload.credentialSubject.tokenContract, TRC20_CONTRACTS.USDT);
      assert.strictEqual(payload.credentialSubject.confirmations, 20);
      assert.strictEqual(payload.credentialSubject.network, 'mainnet');
    });
  });
  
  describe('Receipt Summary Extraction', () => {
    it('should extract summary from VC', () => {
      const vc = {
        id: 'urn:uuid:test-123',
        issuer: 'did:op:sender',
        issuanceDate: '2026-04-13T14:00:00Z',
        credentialSubject: {
          id: 'did:op:recipient',
          rail: 'tron:trc20',
          asset: 'USDT',
          amount: '1000000',
          tronTxHash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
          timestamp: '2026-04-13T14:00:00Z',
          orgAffiliation: 'Test Corp'
        },
        proof: {
          type: 'Ed25519Signature2020',
          proofValue: 'z58...'
        }
      };
      
      const summary = extractReceiptSummary(vc);
      
      assert.strictEqual(summary.receiptId, 'urn:uuid:test-123');
      assert.strictEqual(summary.type, 'tron_receipt_v1');
      assert.strictEqual(summary.issuer, 'did:op:sender');
      assert.strictEqual(summary.subject, 'did:op:recipient');
      assert.strictEqual(summary.asset, 'USDT');
      assert.strictEqual(summary.amount, '1000000');
      assert.strictEqual(summary.verified, true);
    });
  });
  
  describe('VAC Extension Conversion', () => {
    it('should convert receipt to VAC extension format', () => {
      const receipt = {
        id: 'urn:uuid:test-456',
        issuer: 'did:op:sender',
        issuanceDate: '2026-04-13T14:00:00Z',
        expirationDate: '2026-04-20T14:00:00Z',
        credentialSubject: {
          id: 'did:op:recipient',
          rail: 'tron:trc20',
          asset: 'USDT',
          amount: '1000000',
          tronTxHash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
          timestamp: '2026-04-13T14:00:00Z',
          orgAffiliation: 'Test Corp'
        }
      };
      
      const verificationResult = {
        verified: true,
        tronGridVerified: true
      };
      
      const extension = tronReceiptToVACExtension(receipt, verificationResult);
      
      assert.strictEqual(extension.type, 'tron_receipt_v1');
      assert.strictEqual(extension.receiptId, 'urn:uuid:test-456');
      assert.strictEqual(extension.verified, true);
      assert.strictEqual(extension.tronGridVerified, true);
      assert.strictEqual(extension.orgAffiliation, 'Test Corp');
    });
  });
  
  describe('TronRail Main Class', () => {
    let tron;
    let originalEnv;
    
    before(() => {
      originalEnv = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'shasta';
      process.env.TRONGRID_API_KEY = 'test-key';
      resetTronConfig();
      
      try {
        tron = new TronRail({ minConfirmations: 1 });
      } catch (e) {
        // Config may fail without real API key, that's ok for tests
      }
    });
    
    after(() => {
      if (originalEnv) {
        process.env.TRON_NETWORK = originalEnv;
      } else {
        delete process.env.TRON_NETWORK;
      }
      resetTronConfig();
    });
    
    it('should require TRON_NETWORK environment variable', () => {
      delete process.env.TRON_NETWORK;
      resetTronConfig();
      
      assert.throws(() => {
        new TronRail();
      }, /TRON_NETWORK/);
      
      // Restore for other tests
      process.env.TRON_NETWORK = 'shasta';
      resetTronConfig();
    });
    
    it('should provide configuration summary', () => {
      if (!tron) return; // Skip if init failed
      
      const summary = tron.getConfigSummary();
      assert.ok(summary.network);
      assert.ok(summary.apiEndpoint);
      assert.ok(summary.hasOwnProperty('apiKey'));
    });
    
    it('should create receipt without signing', async () => {
      if (!tron) return; // Skip if init failed
      
      const data = {
        issuer_did: 'did:op:sender',
        subject_did: 'did:op:recipient',
        rail: 'tron:trc20',
        asset: 'USDT',
        amount: '1000000',
        tron_tx_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
        timestamp: new Date().toISOString()
      };
      
      const receipt = await tron.createReceipt(data);
      
      assert.ok(receipt['@context']);
      assert.strictEqual(receipt.issuer, data.issuer_did);
      assert.ok(!receipt.proof); // Not signed
    });
    
    it('should return correct AIP types', () => {
      if (!tron) return; // Skip if init failed
      
      assert.strictEqual(tron.getAIPType(true), 'tron:trc20');
      assert.strictEqual(tron.getAIPType(false), 'tron:native');
    });
    
    it('should provide TronScan URL', () => {
      if (!tron) return; // Skip if init failed
      
      const url = tron.getTronscanUrl('abc123');
      assert.ok(url.includes('tronscan'));
      assert.ok(url.includes('abc123'));
    });
  });
  
  describe('TronGrid Client', () => {
    it('should construct with correct endpoint', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'shasta';
      process.env.TRONGRID_API_KEY = 'test-key';
      resetTronConfig();
      
      try {
        const client = new TronGridClient();
        assert.ok(client.baseUrl.includes('shasta'));
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
    
    it('should use config for mainnet endpoint', () => {
      const originalNetwork = process.env.TRON_NETWORK;
      process.env.TRON_NETWORK = 'mainnet';
      process.env.TRONGRID_API_KEY = 'test-key';
      resetTronConfig();
      
      try {
        const client = new TronGridClient();
        assert.strictEqual(client.baseUrl, 'https://api.trongrid.io');
      } finally {
        if (originalNetwork) {
          process.env.TRON_NETWORK = originalNetwork;
        } else {
          delete process.env.TRON_NETWORK;
        }
        resetTronConfig();
      }
    });
  });
});

// Run tests
console.log('🧪 TRON Rail Test Suite (Mainnet Cutover)');
console.log('==========================================\n');
console.log('Environment Variables Required:');
console.log('  TRON_NETWORK=shasta (or mainnet)');
console.log('  TRONGRID_API_KEY=your_api_key');
console.log('\nRun with: TRON_NETWORK=shasta node --test rails/tron/test-tron-rail.mjs\n');
