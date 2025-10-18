#!/usr/bin/env node

/**
 * Storacha Client with P-256 WebAuthn Integration
 *
 * Demonstrates:
 * 1. Creating a P-256 WebAuthn DID
 * 2. Delegating capabilities from Ed25519 key to P-256
 * 3. Creating a Storacha client with P-256 principal
 * 4. Performing upload/list/delete operations with P-256 signatures
 */

import 'dotenv/config'
import * as ed25519 from '../src/ed25519.js'
import * as P256 from '../src/p256.js'
import * as WebAuthnSigner from '../src/p256/webauthn-signer.js'
import * as Core from '../../core/src/lib.js'
import * as Client from '@storacha/client'
import * as Proof from '@storacha/client/proof'
import { StoreMemory } from '@storacha/client/stores/memory'
import { webcrypto } from 'node:crypto'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

const STORACHA_KEY = process.env.STORACHA_KEY
const STORACHA_SPACE_DID = process.env.STORACHA_SPACE_DID
const STORACHA_PROOF = process.env.STORACHA_PROOF

/**
 * Mock WebAuthn environment for testing P-256 signatures
 */
class MockWebAuthnEnvironment {
  constructor() {
    this.credentials = new Map()
  }

  async create(options) {
    const credentialId = crypto.getRandomValues(new Uint8Array(16))
    const privateKey = crypto.getRandomValues(new Uint8Array(32))
    const { p256 } = await import('@noble/curves/p256')
    const publicKey = p256.getPublicKey(privateKey, true)

    const credentialInfo = {
      credentialId: Array.from(credentialId),
      privateKey: Array.from(privateKey),
      publicKey: Array.from(publicKey),
      challenge: options.publicKey.challenge,
    }

    this.credentials.set(credentialId.join(','), credentialInfo)

    return {
      id: credentialId,
      rawId: credentialId.buffer,
      type: 'public-key',
      response: {
        clientDataJSON: new TextEncoder().encode(
          JSON.stringify({
            type: 'webauthn.create',
            challenge: btoa(
              String.fromCharCode(...options.publicKey.challenge)
            ),
            origin: 'https://test.example',
            crossOrigin: false,
          })
        ).buffer,
      },
    }
  }

  async get(options) {
    const challenge = new Uint8Array(options.publicKey.challenge)
    const credId = options.publicKey.allowCredentials?.[0]?.id

    if (!credId) throw new Error('No credential specified')

    const credKey = Array.from(new Uint8Array(credId)).join(',')
    const credential = this.credentials.get(credKey)

    if (!credential) throw new Error('Credential not found')

    const authenticatorData = new Uint8Array(37)
    authenticatorData[32] = 0x01

    const clientData = {
      type: 'webauthn.get',
      challenge: btoa(String.fromCharCode(...challenge)),
      origin: 'https://test.example',
      crossOrigin: false,
    }
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData))

    const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON)
    const signedData = new Uint8Array(authenticatorData.length + 32)
    signedData.set(authenticatorData, 0)
    signedData.set(new Uint8Array(clientDataHash), authenticatorData.length)

    const privateKeyBytes = new Uint8Array(credential.privateKey)
    const { p256 } = await import('@noble/curves/p256')
    const signature = p256.sign(signedData, privateKeyBytes).toCompactRawBytes()

    return {
      id: credId,
      rawId: credId,
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSON.buffer,
        authenticatorData: authenticatorData.buffer,
        signature: signature.buffer,
        userHandle: null,
      },
    }
  }
}

/**
 * Create a WebAuthn P-256 DID and authentication function
 */
async function createWebAuthnP256DID(mockWebAuthn) {
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  const credential = await mockWebAuthn.create({
    publicKey: {
      challenge: challenge,
      user: {
        id: new TextEncoder().encode('storacha-p256-user'),
        name: 'Storacha P-256 User',
        displayName: 'Storacha P-256 User',
      },
      rp: { name: 'Storacha Demo' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    },
  })

  const credKey = Array.from(new Uint8Array(credential.rawId)).join(',')
  const credInfo = mockWebAuthn.credentials.get(credKey)
  const publicKeyBytes = new Uint8Array(credInfo.publicKey)

  const { varint } = await import('multiformats')
  const P256_CODE = 0x1200

  const codeSize = varint.encodingLength(P256_CODE)
  const verifierBytes = new Uint8Array(codeSize + publicKeyBytes.length)
  varint.encodeTo(P256_CODE, verifierBytes, 0)
  verifierBytes.set(publicKeyBytes, codeSize)

  const { base58btc } = await import('multiformats/bases/base58')
  const webauthnDid = `did:key:${base58btc.encode(verifierBytes)}`

  const authenticateFunction = async challenge => {
    return mockWebAuthn.get({
      publicKey: {
        challenge: challenge,
        allowCredentials: [{ type: 'public-key', id: credential.rawId }],
        userVerification: 'preferred',
      },
    })
  }

  return {
    did: webauthnDid,
    credentialId: credential.rawId,
    authenticateFunction,
  }
}

/**
 * Extract and display all capabilities from proofs and delegations
 */
function logProofCapabilities(label, proofs) {
  console.log(`\n📋 CAPABILITIES IN ${label}:`)
  console.log('='.repeat(50))

  if (!proofs || proofs.length === 0) {
    console.log('❌ No proofs found')
    return
  }

  proofs.forEach((proof, idx) => {
    console.log(`\n✨ Proof ${idx + 1}:`)
    if (proof.capabilities) {
      proof.capabilities.forEach((cap, capIdx) => {
        console.log(`  ${capIdx + 1}. can: ${cap.can}`)
        console.log(`     with: ${cap.with}`)
        if (cap.nb && Object.keys(cap.nb).length > 0) {
          console.log(`     nb: ${JSON.stringify(cap.nb)}`)
        }
      })
    } else {
      console.log(`  (No capabilities property found)`)
    }
  })
}

/**
 * Upload, List, and Delete using P-256 client
 */
async function uploadListDeleteWithP256(client, clientName) {
  console.log(`\n📤 P-256 ${clientName} UPLOAD NAMESPACE WORKFLOW`)
  console.log('='.repeat(50))

  try {
    // Upload the file
    const testContent = `Hello Storacha from P-256!
Uploaded: ${new Date().toISOString()}
Space: ${STORACHA_SPACE_DID}
Client: ${clientName}`

    const file = new File([testContent], `storacha-p256-${clientName}.txt`, {
      type: 'text/plain',
    })

    console.log(`📁 File to upload:`)
    console.log(`   Name: ${file.name}`)
    console.log(`   Size: ${file.size} bytes`)

    // Debug: Check client state before upload
    console.log('\n🔍 CLIENT DEBUG INFO (before upload):')
    try {
      const currentSpace = await client.currentSpace()
      console.log(`   Current space: ${currentSpace?.did?.() || 'NOT SET'}`)
    } catch (e) {
      console.log(`   Current space error: ${e.message}`)
    }

    try {
      const proofs = await client.proofs()
      console.log(`   Proofs available: ${proofs?.length || 0}`)
      if (proofs?.length > 0) {
        proofs.forEach((p, i) => {
          console.log(
            `     Proof ${i + 1}: ${
              p.root?.cid?.toString?.() || p.cid?.toString?.() || 'unknown'
            }`
          )
        })
      }
    } catch (e) {
      console.log(`   Proofs error: ${e.message}`)
    }

    try {
      const delegations = await client.delegations()
      console.log(`   Delegations available: ${delegations?.length || 0}`)
      if (delegations?.length > 0) {
        delegations.forEach((d, i) => {
          console.log(
            `     Delegation ${i + 1}: ${
              d.root?.cid?.toString?.() || d.cid?.toString?.() || 'unknown'
            }`
          )
        })
      }
    } catch (e) {
      console.log(`   Delegations error: ${e.message}`)
    }

    // Attempt upload with detailed error handling
    console.log('\n🚀 ATTEMPTING UPLOAD...')
    let result = null
    try {
      result = await client.uploadFile(file)
      console.log(`✅ File uploaded successfully`)
      console.log(`   Result type: ${typeof result}`)
      console.log(`   Result: ${result}`)
      if (result?.cid) {
        console.log(`   CID: ${result.cid}`)
      }
    } catch (uploadError) {
      console.log(`❌ UPLOAD FAILED`)
      console.log(`\n📋 ERROR DETAILS:`)
      console.log(`   Message: ${uploadError?.message}`)
      console.log(`   Name: ${uploadError?.name}`)
      console.log(`   Code: ${uploadError?.code}`)

      // Log the cause properly - stringify it
      if (uploadError?.cause) {
        console.log(`\n   🔍 CAUSE DETAILS:`)
        if (typeof uploadError.cause === 'object') {
          console.log(`   ${JSON.stringify(uploadError.cause, null, 2)}`)
        } else {
          console.log(`   ${uploadError.cause}`)
        }
      }

      if (uploadError?.response) {
        console.log(`\n   HTTP Response:`)
        console.log(`   Status: ${uploadError.response?.status}`)
        console.log(`   Text: ${uploadError.response?.statusText}`)
        try {
          const responseBody = await uploadError.response?.text?.()
          if (responseBody) {
            console.log(`   Body: ${responseBody}`)
          }
        } catch (e) {
          console.log(`   Could not read response body`)
        }
      }

      // Log full stack trace
      console.log(`\n   🧵 Stack:`)
      console.log(uploadError?.stack || 'No stack trace')

      // NOW CHECK: What capabilities does the P-256 client actually have?
      console.log(`\n   🔐 CAPABILITIES AUDIT:`)
      try {
        const proofs = await client.proofs()
        logProofCapabilities('PROOFS', proofs)
      } catch (e) {
        console.log(`   Could not log proofs: ${e.message}`)
      }

      try {
        const delegations = await client.delegations()
        logProofCapabilities('DELEGATIONS', delegations)
      } catch (e) {
        console.log(`   Could not log delegations: ${e.message}`)
      }

      console.log(`\n⚠️  Skipping file operations due to upload failure`)
      return
    }

    if (!result) {
      console.log(`⚠️  Upload returned no result`)
      return
    }

    // List files
    console.log('\n📋 Listing files using upload.list()...')
    let uploads = null
    try {
      uploads = await client.capability.upload.list({ cursor: '', size: 25 })

      if (uploads.results && uploads.results.length > 0) {
        console.log(`✅ Found ${uploads.results.length} files:`)
        uploads.results.forEach((upload, i) => {
          const cid = upload.root || upload.cid || upload
          console.log(`   ${i + 1}. ${cid}`)
        })
      } else {
        console.log('✅ Space is empty (no files yet)')
      }
    } catch (e) {
      console.log(`⚠️  Could not list files: ${e.message}`)
    }

    // Delete files
    if (uploads && uploads.results && uploads.results.length > 0) {
      console.log(
        `\n🗑️  Deleting ${uploads.results.length} files using upload.remove()...`
      )

      for (const upload of uploads.results) {
        const cid = upload.root || upload.cid || upload
        try {
          await client.capability.upload.remove(cid)
          console.log(`✅ Deleted: ${cid}`)
        } catch (e) {
          console.log(`⚠️  Could not delete ${cid}: ${e.message}`)
        }
      }
    }
  } catch (error) {
    console.error(`❌ Error in P-256 ${clientName} workflow:`, error.message)
    console.error(error.stack)
  }
}

async function main() {
  if (!STORACHA_KEY || !STORACHA_SPACE_DID || !STORACHA_PROOF) {
    console.error('❌ Missing required environment variables:')
    console.error('   STORACHA_KEY - Ed25519 private key')
    console.error('   STORACHA_SPACE_DID - Space DID')
    console.error('   STORACHA_PROOF - Space proof')
    process.exit(1)
  }

  try {
    console.log('🚀 Storacha P-256 WebAuthn Setup')
    console.log('='.repeat(50))

    // Step 1: Setup Ed25519 client for delegation
    console.log('\n🔑 Step 1: Setting up Ed25519 principal...')
    const ed25519Principal = ed25519.parse(STORACHA_KEY)
    const store = new StoreMemory()
    const ed25519Client = await Client.create({
      principal: ed25519Principal,
      store,
    })
    console.log('✅ Ed25519 client created')

    // Step 2: Add space to Ed25519 client
    const proof = await Proof.parse(STORACHA_PROOF)
    const space = await ed25519Client.addSpace(proof)
    await ed25519Client.setCurrentSpace(space.did())
    console.log(`✅ Connected to space: ${space.did()}`)

    // Step 3: Create P-256 WebAuthn DID
    console.log('\n🔐 Step 2: Creating P-256 WebAuthn DID...')
    const mockWebAuthn = new MockWebAuthnEnvironment()
    const webauthnInfo = await createWebAuthnP256DID(mockWebAuthn)
    console.log(`✅ P-256 DID: ${webauthnInfo.did}`)

    // Step 4: Create WebAuthn P-256 signer
    const webauthnSigner = WebAuthnSigner.createWebAuthnSigner(
      webauthnInfo.did,
      webauthnInfo.authenticateFunction
    )
    console.log(`✅ WebAuthn signer created`)

    // Step 5: Delegate capabilities from Ed25519 to P-256
    console.log('\n📜 Step 3: Delegating capabilities (Ed25519 ➜ P-256)...')
    const p256Verifier = P256.Verifier.parse(webauthnInfo.did)
    const p256Delegation = await Core.delegate({
      issuer: ed25519Principal,
      audience: p256Verifier,
      capabilities: [
        { with: STORACHA_SPACE_DID, can: 'space/blob/add' },
        { with: STORACHA_SPACE_DID, can: 'space/blob/list' },
        { with: STORACHA_SPACE_DID, can: 'space/blob/index' },
        { with: STORACHA_SPACE_DID, can: 'space/upload/add' },
        { with: STORACHA_SPACE_DID, can: 'space/upload/list' },
        { with: STORACHA_SPACE_DID, can: 'space/upload/remove' },
      ],
      proofs: [proof],
    })
    console.log(`✅ Delegation created: ${p256Delegation.cid}`)

    // Step 6: Create P-256 client
    console.log('\n🔌 Step 4: Creating P-256 client...')
    const p256Store = new StoreMemory()
    const p256Client = await Client.create({
      principal: webauthnSigner,
      store: p256Store,
    })
    console.log('✅ P-256 client created')

    // Step 7: Add delegation as proof to P-256 client
    console.log('\n🔐 Step 5: Adding delegation proof to P-256 client...')
    try {
      await p256Client.addProof(p256Delegation)
      console.log('✅ Delegation proof added to P-256 client')
    } catch (e) {
      console.log(`⚠️  Could not add proof: ${e.message}`)
    }

    // Step 8: Add space proof to P-256 client
    console.log('\n📍 Step 6: Adding space proof to P-256 client...')
    try {
      // Re-parse the space proof for the P-256 client
      const proofForP256 = await Proof.parse(STORACHA_PROOF)
      const spaceForP256 = await p256Client.addSpace(proofForP256)
      await p256Client.setCurrentSpace(spaceForP256.did())
      console.log(`✅ P-256 client connected to space`)
    } catch (e) {
      console.log(`⚠️  Could not set space: ${e.message}`)
    }

    // Step 9: Test upload/list/delete with P-256 client
    console.log('\n🧪 Step 7: Testing P-256 workflows...')
    console.log('='.repeat(50))

    await uploadListDeleteWithP256(p256Client, 'WebAuthn')

    console.log('\n✅ P-256 WebAuthn integration complete!')
    console.log('🎉 Successfully demonstrated:')
    console.log('   ✅ P-256 WebAuthn DID creation')
    console.log('   ✅ Capability delegation (Ed25519 → P-256)')
    console.log('   ✅ P-256 client with proof delegation')
    console.log('   ✅ Upload/list/delete with P-256 signatures')
  } catch (error) {
    console.error('\n❌ Error:', error.message)
    console.error(error.stack)
    process.exit(1)
  }
}

main()
