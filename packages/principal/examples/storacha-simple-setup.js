#!/usr/bin/env node

/**
 * Storacha Client with Upload and Blob Namespace Functions
 *
 * Two functions demonstrate:
 * 1. uploadListDelete() - uses upload namespace
 * 2. blobListDelete() - uses blob namespace
 */

import 'dotenv/config'
import * as Signer from '@storacha/client/principal/ed25519'
import { StoreMemory } from '@storacha/client/stores/memory'
import * as Client from '@storacha/client'
import * as Proof from '@storacha/client/proof'
import { CID } from 'multiformats/cid'

const STORACHA_KEY = process.env.STORACHA_KEY
const STORACHA_SPACE_DID = process.env.STORACHA_SPACE_DID
const STORACHA_PROOF = process.env.STORACHA_PROOF

/**
 * Upload, List, and Delete using upload namespace
 */
async function uploadListDelete(client) {
  console.log('\n📤 UPLOAD NAMESPACE WORKFLOW')
  console.log('='.repeat(50))

  try {
    // Upload the file
    const testContent = `Hello Storacha!
    Uploaded: ${new Date().toISOString()}
    Space: ${STORACHA_SPACE_DID}`

    const file = new File([testContent], 'storacha-test-upload.txt', {
      type: 'text/plain',
    })

    console.log(`📁 File to upload:`)
    console.log(`   Name: ${file.name}`)
    console.log(`   Size: ${file.size} bytes`)

    const result = await client.uploadFile(file)
    console.log(`✅ File uploaded: ${result}`)

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
    console.error('❌ Error in uploadListDelete:', error.message)
  }
}

/**
 * Upload, List, and Delete using blob namespace
 */
async function blobListDelete(client) {
  console.log('\n🧱 BLOB NAMESPACE WORKFLOW')
  console.log('='.repeat(50))

  try {
    // Upload the file
    const testContent = `Hello Storacha Blob!
    Uploaded: ${new Date().toISOString()}
    Space: ${STORACHA_SPACE_DID}`

    const file = new File([testContent], 'storacha-test-blob.txt', {
      type: 'text/plain',
    })

    console.log(`📁 File to upload:`)
    console.log(`   Name: ${file.name}`)
    console.log(`   Size: ${file.size} bytes`)

    const result = await client.uploadFile(file)
    console.log(`✅ File uploaded: ${result}`)

    // List files using blob namespace
    console.log('\n📋 Listing files using blob.list()...')
    let blobs = null
    try {
      blobs = await client.capability.blob.list({ cursor: '', size: 25 })

      if (blobs.results && blobs.results.length > 0) {
        console.log(`✅ Found ${blobs.results.length} blobs:`)
        blobs.results.forEach((blob, i) => {
          // Use blob.blob.digest, not blob.cause!
          const digest =
            blob.blob && blob.blob.digest
              ? Buffer.from(blob.blob.digest).toString('base64')
              : blob.toString()
          console.log(`   ${i + 1}. ${digest}`)
        })
      } else {
        console.log('✅ Space has no blobs yet')
      }
    } catch (e) {
      console.log(`⚠️  Could not list blobs: ${e.message}`)
    }

    // Delete blobs
    if (blobs && blobs.results && blobs.results.length > 0) {
      console.log(
        `\n🗑️  Deleting ${blobs.results.length} blobs using blob.remove()...`
      )

      for (const blob of blobs.results) {
        try {
          // Extract the digest from blob.blob.digest (it's a Uint8Array)
          if (blob.blob && blob.blob.digest) {
            const digest = new Uint8Array(blob.blob.digest)
            await client.capability.blob.remove({ bytes: digest })
            const digestStr = Buffer.from(digest).toString('base64')
            console.log(`✅ Deleted: ${digestStr}`)
          } else {
            console.log(`⚠️  Invalid blob structure: missing blob.blob.digest`)
          }
        } catch (e) {
          console.log(`⚠️  Could not delete blob: ${e.message}`)
        }
      }
    }
  } catch (error) {
    console.error('❌ Error in blobListDelete:', error.message)
  }
}

/**
 * Extracts all capabilities from a proof/delegation
 * @param {API.Delegation} proof - The parsed proof
 * @returns {Array} Array of capabilities with details
 */
function extractCapabilitiesFromProof(proof) {
  const capabilities = []

  // Helper function to recursively iterate through delegations
  function iterateProofCapabilities(delegation, depth = 0) {
    // Get direct capabilities from this delegation
    if (delegation.capabilities) {
      for (const cap of delegation.capabilities) {
        capabilities.push({
          depth,
          with: cap.with,
          can: cap.can,
          nb: cap.nb || {},
          issuer: delegation.issuer?.did?.() || delegation.issuer,
          audience: delegation.audience?.did?.() || delegation.audience,
        })
      }
    }

    // Recursively check proofs (for delegation chains)
    if (delegation.proofs && Array.isArray(delegation.proofs)) {
      for (const proof of delegation.proofs) {
        // Only process included delegations, not links
        if (proof.capabilities) {
          iterateProofCapabilities(proof, depth + 1)
        }
      }
    }
  }

  iterateProofCapabilities(proof)
  return capabilities
}

/**
 * Prints all capabilities from a proof in a readable format
 * @param {API.Delegation} proof - The parsed proof
 */
function logAllCapabilities(proof) {
  console.log('\n📋 ALL CAPABILITIES IN PROOF:')
  console.log('='.repeat(50))

  const capabilities = extractCapabilitiesFromProof(proof)

  if (capabilities.length === 0) {
    console.log('❌ No capabilities found in proof!')
    return
  }

  // Group by resource (with) and ability (can)
  const grouped = {}
  for (const cap of capabilities) {
    const resource = cap.with
    const ability = cap.can
    const key = `${resource}#${ability}`

    if (!grouped[key]) {
      grouped[key] = []
    }
    grouped[key].push(cap)
  }

  // Log grouped capabilities
  let count = 1
  for (const [key, caps] of Object.entries(grouped)) {
    const [resource, ability] = key.split('#')
    console.log(`\n${count}. Resource: ${resource}`)
    console.log(`   Ability: ${ability}`)
    console.log(`   Occurrences: ${caps.length}`)

    // Show constraints if any
    for (const cap of caps) {
      if (Object.keys(cap.nb).length > 0) {
        console.log(`   Constraints: ${JSON.stringify(cap.nb)}`)
      }
    }
    count++
  }

  console.log('\n' + '='.repeat(50))
  console.log(
    `✅ Total capability combinations: ${Object.keys(grouped).length}`
  )

  // Check for specific capabilities
  const hasSpaceBlobRemove = capabilities.some(
    cap =>
      cap.can === 'space/blob/remove' ||
      (cap.can === '*' && cap.with.includes('space')) ||
      (cap.can === '*' && cap.with === 'ucan:*')
  )

  if (!hasSpaceBlobRemove) {
    console.log('⚠️  WARNING: space/blob/remove capability NOT found!')
  } else {
    console.log('✅ space/blob/remove capability is available')
  }
}

async function main() {
  if (!STORACHA_KEY || !STORACHA_SPACE_DID) {
    console.error('❌ Missing required environment variables:')
    console.error('   STORACHA_KEY - Ed25519 private key')
    console.error('   STORACHA_SPACE_DID - Space DID')
    process.exit(1)
  }

  try {
    console.log('🚀 Storacha Upload & List Example')
    console.log('='.repeat(50))

    // Setup
    const principal = Signer.parse(STORACHA_KEY)
    const store = new StoreMemory()
    const client = await Client.create({ principal, store })
    console.log('✅ Client created')

    const proof = await Proof.parse(STORACHA_PROOF)

    // Extract and log all capabilities BEFORE adding the space
    logAllCapabilities(proof)

    const space = await client.addSpace(proof)
    await client.setCurrentSpace(space.did())
    console.log(`✅ Connected to space: ${space.did()}`)

    // Run upload namespace workflow
    await uploadListDelete(client)

    // Run blob namespace workflow
    await blobListDelete(client)

    console.log('\n✅ All workflows completed!')
  } catch (error) {
    console.error('\n❌ Error:', error.message)
    process.exit(1)
  }
}

main()
