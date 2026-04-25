/**
 * TRON TRC-20 Send Module
 *
 * Executes TRC-20 USDT transfers on TRON mainnet (or testnet).
 * Used by /v1/settlement/execute endpoint.
 *
 * Reuses tron-config.mjs for network configuration.
 * Requires TRON_DEMO_SENDER_PRIVATE_KEY env var for the sending wallet.
 *
 * Usage (from Python subprocess):
 *   node -e "import('./tron-send.mjs').then(m => m.sendTrc20(JSON.parse(process.argv[1]))).then(r => console.log(JSON.stringify(r))).catch(e => console.log(JSON.stringify({error: e.message})))" '{"to":"T...","amount":"100000","contract":"TR7..."}'
 */

import TronWeb from 'tronweb';
import { getTronConfig, MAINNET_USDT_CONTRACT } from './tron-config.mjs';

/**
 * Send TRC-20 tokens (USDT) on TRON.
 *
 * @param {Object} params
 * @param {string} params.to - Destination TRON address (base58)
 * @param {string} params.amount - Amount in human units (e.g. "0.10" for 0.10 USDT)
 * @param {string} [params.contract] - TRC-20 contract address (defaults to USDT)
 * @returns {Object} { txHash, blockNumber, tronscanUrl, confirmedAt }
 */
export async function sendTrc20(params) {
    const { to, amount, contract } = params;

    const config = getTronConfig();
    const networkConfig = config.getConfig();
    const privateKey = process.env.TRON_DEMO_SENDER_PRIVATE_KEY;

    if (!privateKey) {
        throw new Error('TRON_DEMO_SENDER_PRIVATE_KEY environment variable is not set');
    }

    // Validate destination address
    if (!to || !to.startsWith('T') || to.length !== 34) {
        throw new Error(`Invalid TRON destination address: ${to}`);
    }

    // Parse amount: convert human units to sun (6 decimals for USDT)
    const amountFloat = parseFloat(amount);
    if (isNaN(amountFloat) || amountFloat <= 0) {
        throw new Error(`Invalid amount: ${amount}`);
    }
    const amountSun = Math.round(amountFloat * 1e6);

    // Use provided contract or default to network's USDT
    const tokenContract = contract || networkConfig.usdtContract;
    if (!tokenContract) {
        throw new Error(`No USDT contract configured for network ${networkConfig.name}. Provide contract address explicitly.`);
    }

    // Initialize TronWeb with the sender's private key
    const tronWeb = new TronWeb({
        fullHost: networkConfig.apiEndpoint,
        headers: networkConfig.apiKey ? { 'TRON-PRO-API-KEY': networkConfig.apiKey } : {},
        privateKey: privateKey,
    });

    const senderAddress = tronWeb.address.fromPrivateKey(privateKey);

    // Build TRC-20 transfer transaction
    const functionSelector = 'transfer(address,uint256)';
    const parameter = [
        { type: 'address', value: to },
        { type: 'uint256', value: amountSun },
    ];

    const transaction = await tronWeb.transactionBuilder.triggerSmartContract(
        tokenContract,
        functionSelector,
        { feeLimit: 50_000_000 }, // 50 TRX fee limit
        parameter,
        senderAddress,
    );

    if (!transaction.result || !transaction.result.result) {
        throw new Error(`Failed to build transaction: ${JSON.stringify(transaction)}`);
    }

    // Sign and broadcast
    const signedTx = await tronWeb.trx.sign(transaction.transaction);
    const broadcast = await tronWeb.trx.sendRawTransaction(signedTx);

    if (!broadcast.result) {
        throw new Error(`Broadcast failed: ${JSON.stringify(broadcast)}`);
    }

    const txHash = broadcast.txid || signedTx.txID;
    const tronscanUrl = config.getTronscanTxUrl(txHash);

    return {
        txHash,
        senderAddress,
        destinationAddress: to,
        amount: amount,
        amountSun: amountSun.toString(),
        contract: tokenContract,
        network: networkConfig.name,
        tronscanUrl,
        // blockNumber and confirmedAt populated after confirmation
        blockNumber: null,
        confirmedAt: new Date().toISOString(),
    };
}

// CLI entry point for subprocess calls
const args = process.argv.slice(2);
if (args.length > 0) {
    try {
        const params = JSON.parse(args[0]);
        sendTrc20(params)
            .then(result => {
                console.log(JSON.stringify(result));
                process.exit(0);
            })
            .catch(err => {
                console.log(JSON.stringify({ error: err.message }));
                process.exit(1);
            });
    } catch (e) {
        console.log(JSON.stringify({ error: `Invalid JSON input: ${e.message}` }));
        process.exit(1);
    }
}
