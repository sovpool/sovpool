#!/usr/bin/env bash
# Signet Demo — CTV Payment Pool on Bitcoin Inquisition Signet
#
# Prerequisites:
#   1. Bitcoin Inquisition v29.2+ running on signet with txindex=1
#   2. A funded wallet with signet coins (get from https://signetfaucet.com/)
#   3. sovpool CLI built: cargo build --release
#
# Usage:
#   ./scripts/signet-demo.sh [bitcoind-datadir]
#
# Environment:
#   BITCOIN_CLI  — path to bitcoin-cli (default: bitcoin-cli)
#   SOVPOOL_CLI  — path to sovpool binary (default: ./target/release/sovpool)

set -euo pipefail

BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
SOVPOOL_CLI="${SOVPOOL_CLI:-./target/release/sovpool}"
DATADIR="${1:-$HOME/.bitcoin}"
CLI="$BITCOIN_CLI -signet -datadir=$DATADIR"

echo "=== sovpool Signet Demo ==="
echo "Using bitcoin-cli: $BITCOIN_CLI"
echo "Using sovpool:     $SOVPOOL_CLI"
echo "Signet datadir:    $DATADIR"
echo

# Check connectivity
echo "--- Step 0: Check signet node ---"
BLOCK_COUNT=$($CLI getblockcount 2>/dev/null) || {
    echo "ERROR: Cannot connect to signet node."
    echo "Start Bitcoin Inquisition with: bitcoind -signet -txindex -server -datadir=$DATADIR"
    exit 1
}
echo "Signet block height: $BLOCK_COUNT"

WALLET="sovpool-demo"
WCLI="$CLI -rpcwallet=$WALLET"

# Ensure wallet exists
$WCLI getbalance >/dev/null 2>&1 || {
    echo "Creating wallet '$WALLET'..."
    $CLI createwallet "$WALLET" >/dev/null 2>&1 || $CLI loadwallet "$WALLET" >/dev/null 2>&1
}
BALANCE=$($WCLI getbalance 2>/dev/null)
echo "Wallet balance: $BALANCE BTC"
echo

if [ "$BALANCE" = "0.00000000" ]; then
    ADDR=$($WCLI getnewaddress "" bech32m)
    echo "Wallet is empty. Get signet coins from a faucet:"
    echo "  https://signetfaucet.com/"
    echo "  Address: $ADDR"
    echo
    echo "After funding, wait for 1 confirmation and re-run this script."
    exit 0
fi

# Step 1: Create a 3-party pool with P2A anchor
echo "--- Step 1: Create 3-party pool ---"
POOL_JSON=$($SOVPOOL_CLI pool create -n 3 --amount 10000 --network signet --anchor -f json)
echo "$POOL_JSON" > /tmp/sovpool-demo-pool.json
echo "$POOL_JSON" | python3 -m json.tool 2>/dev/null || echo "$POOL_JSON"

POOL_ADDR=$(echo "$POOL_JSON" | python3 -c "import sys,json; p=json.load(sys.stdin); print(p.get('address',''))" 2>/dev/null)
if [ -z "$POOL_ADDR" ]; then
    # Fallback: use CLI summary mode to get address
    POOL_ADDR=$($SOVPOOL_CLI pool create -n 3 --amount 10000 --network signet --anchor -f summary 2>&1 | grep "Address:" | awk '{print $2}')
fi
echo "Pool address: $POOL_ADDR"
echo

# Step 2: Fund the pool
echo "--- Step 2: Fund pool (30,000 sats = 0.0003 BTC) ---"
FUND_TXID=$($WCLI sendtoaddress "$POOL_ADDR" 0.0003)
echo "Funding txid: $FUND_TXID"
echo "Explorer: https://mempool.space/signet/tx/$FUND_TXID"
echo
echo "Waiting for confirmation..."
$WCLI -named generatetoaddress nblocks=1 address="$($WCLI getnewaddress)" >/dev/null 2>&1 || true

# Wait for confirmation (signet blocks ~10 min)
echo "On signet, blocks take ~10 minutes. Waiting for 1 confirmation..."
for i in $(seq 1 60); do
    CONFS=$($WCLI gettransaction "$FUND_TXID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('confirmations',0))" 2>/dev/null || echo 0)
    if [ "$CONFS" -ge 1 ] 2>/dev/null; then
        echo "Confirmed in block! Confirmations: $CONFS"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "Still unconfirmed after 10 minutes. On signet this is normal."
        echo "Re-run the script after the transaction confirms."
        echo "Check: $WCLI gettransaction $FUND_TXID"
        exit 0
    fi
    sleep 10
done
echo

# Step 3: Find pool UTXO
echo "--- Step 3: Locate pool UTXO ---"
RAW_TX=$($WCLI getrawtransaction "$FUND_TXID" true 2>/dev/null || $CLI getrawtransaction "$FUND_TXID" true)
POOL_VOUT=$(echo "$RAW_TX" | python3 -c "
import sys, json
tx = json.load(sys.stdin)
pool_addr = '$POOL_ADDR'
for i, out in enumerate(tx['vout']):
    if out.get('scriptPubKey',{}).get('address','') == pool_addr:
        print(i)
        break
" 2>/dev/null || echo "0")
echo "Pool UTXO: $FUND_TXID:$POOL_VOUT"
echo

# Step 4: Build and broadcast exit transaction
echo "--- Step 4: Exit participant 0 ---"
EXIT_HEX=$($SOVPOOL_CLI pool exit --pool-utxo "$FUND_TXID:$POOL_VOUT" --participant 0 --pool-file /tmp/sovpool-demo-pool.json)
echo "Exit tx hex (first 80 chars): ${EXIT_HEX:0:80}..."
echo

echo "Broadcasting exit transaction..."
EXIT_TXID=$($WCLI sendrawtransaction "$EXIT_HEX" 2>/dev/null || $CLI sendrawtransaction "$EXIT_HEX") || {
    echo "Broadcast failed. The raw transaction:"
    echo "$EXIT_HEX"
    echo
    echo "Try broadcasting manually:"
    echo "  $CLI sendrawtransaction $EXIT_HEX"
    exit 1
}
echo "Exit txid: $EXIT_TXID"
echo "Explorer: https://mempool.space/signet/tx/$EXIT_TXID"
echo

echo "=== Demo Complete ==="
echo
echo "Summary:"
echo "  Pool funding tx:  $FUND_TXID"
echo "  Pool address:     $POOL_ADDR"
echo "  Exit tx:          $EXIT_TXID"
echo
echo "View on explorer:"
echo "  https://mempool.space/signet/tx/$FUND_TXID"
echo "  https://mempool.space/signet/tx/$EXIT_TXID"
