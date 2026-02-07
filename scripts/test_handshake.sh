#!/bin/bash
# Test script for VPN server handshake and data channel debugging

set -e

cd "$(dirname "$0")"

# Configuration
SERVER_BIN="../build/demos/simple_vpn_server"
SERVER_CONFIG="../configs/server_config.json"
CLIENT_CONFIG="../test_data/test_client.ovpn"
TEST_DURATION=8
PING_IP="10.8.0.1"

# Log files
SERVER_LOG="/tmp/vpn_server_test.log"
CLIENT_LOG="/tmp/vpn_client_test.log"
PING_LOG="/tmp/vpn_ping_test.log"

echo "==================================================================="
echo "VPN Handshake & Data Channel Test Script"
echo "==================================================================="

# Clean up any existing processes
echo "[1/6] Cleaning up existing processes..."
sudo pkill -9 simple_vpn_server openvpn 2>/dev/null || true
sudo fuser -k 1194/udp 2>/dev/null || true
sleep 2

# Remove old logs
rm -f "$SERVER_LOG" "$CLIENT_LOG" "$PING_LOG"

# Start server
echo "[2/7] Starting VPN server..."
sudo "$SERVER_BIN" "$SERVER_CONFIG" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 3

# Verify server is running
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "ERROR: Server failed to start!"
    cat "$SERVER_LOG"
    exit 1
fi
echo "        Server started (PID: $SERVER_PID)"

# Start client
echo "[3/7] Starting OpenVPN client..."
sudo openvpn --config "$CLIENT_CONFIG" --verb 3 > "$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
echo "        Client started (PID: $CLIENT_PID)"

# Wait for handshake
echo "[4/7] Waiting ${TEST_DURATION}s for handshake..."
sleep $TEST_DURATION

# Test data channel with ping
echo "[5/7] Testing data channel (ping $PING_IP)..."
ping -c 5 -W 2 $PING_IP > "$PING_LOG" 2>&1 && PING_SUCCESS=1 || PING_SUCCESS=0

if [ $PING_SUCCESS -eq 1 ]; then
    echo "        ✓ Ping successful - data channel is working!"
else
    echo "        ✗ Ping failed - data channel not working"
fi

# Stop both processes
echo "[6/7] Stopping processes..."
sudo kill -2 $SERVER_PID $CLIENT_PID 2>/dev/null || true
sleep 2
sudo pkill -9 simple_vpn_server openvpn 2>/dev/null || true

# Display results
echo "[7/7] Results:"
echo ""
echo "==================================================================="
echo "PING TEST RESULTS:"
echo "==================================================================="
cat "$PING_LOG"

echo ""
echo "==================================================================="
echo "CLIENT STATUS:"
echo "==================================================================="
grep -iE "Initialization Sequence|Data Channel|cipher|peer-id|DCO" "$CLIENT_LOG" || echo "No status found"

echo ""
echo "==================================================================="
echo "SERVER LOG (last 80 lines):"
echo "==================================================================="
tail -80 "$SERVER_LOG"

echo ""
echo "==================================================================="
echo "DATA CHANNEL PACKETS:"
echo "==================================================================="
echo "Server data packets received:"
grep -c "Received data packet" "$SERVER_LOG" || echo "0"
echo ""
echo "Server data packets decrypted:"
grep -c "Decrypted.*data" "$SERVER_LOG" || echo "0"

echo ""
echo "==================================================================="
echo "Test complete. Full logs at:"
echo "  Server: $SERVER_LOG"
echo "  Client: $CLIENT_LOG"
echo "  Ping:   $PING_LOG"
echo "==================================================================="
