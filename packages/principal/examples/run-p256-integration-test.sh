#!/bin/bash

# P-256 WebAuthn Storacha Integration Test Runner
# This script sets up environment variables and runs the integration test

set -e

echo "🔗 P-256 WebAuthn Storacha Integration Test Runner"
echo "================================================="

# Check if .env file exists
if [ ! -f .env ]; then
    echo "❌ .env file not found!"
    echo ""
    echo "Please create .env file with your Storacha credentials:"
    echo "1. Copy .env.example to .env"
    echo "2. Fill in your Storacha credentials from https://console.storacha.network/"
    echo ""
    echo "Required variables:"
    echo "  - STORACHA_KEY: Your Ed25519 private key (base64)"
    echo "  - STORACHA_PROOF: Your space proof (base64)"  
    echo "  - STORACHA_SPACE_DID: Your space DID (did:key format)"
    echo ""
    exit 1
fi

# Load environment variables
echo "📋 Loading environment variables from .env..."
set -a  # automatically export all variables
source .env
set +a

# Validate required environment variables
echo "🔍 Validating environment variables..."

if [ -z "$STORACHA_KEY" ]; then
    echo "❌ STORACHA_KEY is not set"
    exit 1
fi

if [ -z "$STORACHA_PROOF" ]; then
    echo "❌ STORACHA_PROOF is not set"
    exit 1
fi

if [ -z "$STORACHA_SPACE_DID" ]; then
    echo "❌ STORACHA_SPACE_DID is not set"
    exit 1
fi

# Validate DID format
if [[ ! $STORACHA_SPACE_DID == did:key:* ]]; then
    echo "❌ STORACHA_SPACE_DID must start with 'did:key:'"
    exit 1
fi

echo "✅ Environment variables validated"
echo ""

# Show configuration (safely)
echo "📋 Test Configuration:"
echo "   Storacha Key: ${STORACHA_KEY:0:20}..."
echo "   Storacha Proof: ${STORACHA_PROOF:0:20}..."
echo "   Storacha Space: $STORACHA_SPACE_DID"
echo ""

# Run the integration test
echo "🚀 Running P-256 WebAuthn Storacha integration test..."
echo ""

node p256-storacha-integration.test.js

# Check if result file was created
if [ -f "p256-storacha-integration-result.json" ]; then
    echo ""
    echo "📄 Test results saved to: p256-storacha-integration-result.json"
    echo "📊 Result summary:"
    cat p256-storacha-integration-result.json | jq -r '
        "   Timestamp: " + .timestamp + 
        "\n   Ed25519 DID: " + .ed25519_did + 
        "\n   P-256 WebAuthn DID: " + .p256_webauthn_did + 
        "\n   Space DID: " + .space_did +
        "\n   File CID: " + .file_cid +
        "\n   Signature Valid: " + (.signature_valid | tostring) +
        "\n   Invocation Size: " + (.invocation_size | tostring) + " bytes"
    ' 2>/dev/null || {
        echo "   (JSON parsing unavailable - check file directly)"
    }
fi

echo ""
echo "🎉 Integration test completed!"
echo ""
echo "💡 Next steps:"
echo "   1. Review the generated result file"
echo "   2. Adapt for browser environment with real WebAuthn"
echo "   3. Connect to live Storacha endpoints"
echo "   4. Test with hardware security keys"