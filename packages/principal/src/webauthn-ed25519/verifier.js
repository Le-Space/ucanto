/**
 * WebAuthn Ed25519 Verifier with Varsig Support
 * 
 * Verifies varsig-encoded WebAuthn signatures
 */

import { varint } from 'multiformats'
import * as Verifier from '../ed25519/verifier.js'

export const code = Verifier.code // Same as Ed25519
export const name = 'Ed25519'
export const signatureAlgorithm = Verifier.signatureAlgorithm
export const signatureCode = Verifier.signatureCode

// Varsig multicodec for WebAuthn Ed25519
export const VARSIG_WEBAUTHN_ED25519 = 0xd1ed

/**
 * Create verifier from public key and DID
 * 
 * @param {Uint8Array} publicKey - Raw Ed25519 public key (32 bytes)
 * @param {string} did - DID string
 * @returns {WebAuthnEd25519Verifier}
 */
export const create = (publicKey, did) => {
  return new WebAuthnEd25519Verifier(publicKey, did)
}

/**
 * WebAuthn Ed25519 Verifier
 */
class WebAuthnEd25519Verifier {
  /**
   * @param {Uint8Array} publicKey 
   * @param {string} didString
   */
  constructor(publicKey, didString) {
    this.publicKey = publicKey
    this._did = didString
  }

  get code() {
    return code
  }

  /**
   * @returns {import('../ed25519/type.js').DID<'key'>}
   */
  did() {
    return /** @type {import('../ed25519/type.js').DID<'key'>} */ (this._did)
  }

  /**
   * @returns {import('../ed25519/type.js').DID<'key'>}
   */
  toDIDKey() {
    return /** @type {import('../ed25519/type.js').DID<'key'>} */ (this._did)
  }

  /**
   * @template {import('../ed25519/type.js').DID} ID
   * @param {ID} id
   * @returns {WebAuthnEd25519Verifier & {did(): ID, toDIDKey(): ID}}
   */
  withDID(id) {
    const verifier = new WebAuthnEd25519Verifier(this.publicKey, id)
    return /** @type {WebAuthnEd25519Verifier & {did(): ID, toDIDKey(): ID}} */ (verifier)
  }

  /**
   * Verify varsig-encoded signature
   * 
   * @template T
   * @param {import('../ed25519/type.js').ByteView<T>} payload
   * @param {import('../ed25519/type.js').Signature<T, typeof signatureCode>} signature
   * @returns {Promise<boolean>}
   */
  async verify(payload, signature) {
    try {
      // Decode varsig from signature.raw
      const decoded = decodeVarsig(signature.raw)
      
      // The payload was hashed to create the WebAuthn challenge
      // We need to verify that the challenge matches
      const payloadHash = await crypto.subtle.digest('SHA-256', payload)
      const expectedChallenge = new Uint8Array(payloadHash)
      
      // Parse clientDataJSON to get the actual challenge
      const clientDataText = new TextDecoder().decode(decoded.clientDataJSON)
      const clientData = JSON.parse(clientDataText)
      const actualChallenge = base64urlToBytes(clientData.challenge)
      
      // Verify challenge matches
      if (!bytesEqual(expectedChallenge, actualChallenge)) {
        console.error('[ucanto-varsig] Challenge mismatch')
        return false
      }
      
      // Reconstruct the signed data: authenticatorData || SHA-256(clientDataJSON)
      const clientDataHash = await crypto.subtle.digest('SHA-256', decoded.clientDataJSON)
      const signedData = new Uint8Array(
        decoded.authenticatorData.length + clientDataHash.byteLength
      )
      signedData.set(decoded.authenticatorData, 0)
      signedData.set(new Uint8Array(clientDataHash), decoded.authenticatorData.length)
      
      // Verify Ed25519 signature
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        this.publicKey,
        { name: 'Ed25519' },
        false,
        ['verify']
      )
      
      const valid = await crypto.subtle.verify(
        'Ed25519',
        cryptoKey,
        decoded.signature,
        signedData
      )
      
      if (valid) {
        console.log('✅ [ucanto-varsig] Signature verified successfully')
      } else {
        console.error('❌ [ucanto-varsig] Signature verification failed')
      }
      
      return valid
    } catch (error) {
      console.error('[ucanto-varsig] Verification error:', error)
      return false
    }
  }

  get signatureAlgorithm() {
    return signatureAlgorithm
  }

  get signatureCode() {
    return signatureCode
  }
}

/**
 * Decode varsig format
 * Format: [multicodec][authData_len][authData][clientData_len][clientData][signature]
 * 
 * @param {Uint8Array} varsig
 * @returns {{authenticatorData: Uint8Array, clientDataJSON: Uint8Array, signature: Uint8Array}}
 */
function decodeVarsig(varsig) {
  let offset = 0
  
  // Decode multicodec
  const [multicodec, multicodecLen] = decodeVarint(varsig, offset)
  offset += multicodecLen
  
  // Decode authenticatorData length
  const [authDataLen, authDataLenSize] = decodeVarint(varsig, offset)
  offset += authDataLenSize
  
  // Extract authenticatorData
  const authenticatorData = varsig.slice(offset, offset + authDataLen)
  offset += authDataLen
  
  // Decode clientDataJSON length
  const [clientDataLen, clientDataLenSize] = decodeVarint(varsig, offset)
  offset += clientDataLenSize
  
  // Extract clientDataJSON
  const clientDataJSON = varsig.slice(offset, offset + clientDataLen)
  offset += clientDataLen
  
  // Extract signature (rest of the bytes)
  const signature = varsig.slice(offset)
  
  return {
    authenticatorData,
    clientDataJSON,
    signature
  }
}

/**
 * Decode varint
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {[number, number]} [value, bytesRead]
 */
function decodeVarint(bytes, offset = 0) {
  let value = 0
  let shift = 0
  let bytesRead = 0
  
  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead]
    bytesRead++
    
    value |= (byte & 0x7f) << shift
    
    if ((byte & 0x80) === 0) {
      return [value, bytesRead]
    }
    
    shift += 7
  }
  
  throw new Error('Varint incomplete')
}

/**
 * Convert base64url to Uint8Array
 * @param {string} base64url
 * @returns {Uint8Array}
 */
function base64urlToBytes(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const padding = '='.repeat((4 - (base64.length % 4)) % 4)
  const paddedBase64 = base64 + padding
  const binaryString = atob(paddedBase64)
  const bytes = new Uint8Array(binaryString.length)
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }
  return bytes
}

/**
 * Compare two Uint8Arrays for equality
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/**
 * Standalone varsig verification function
 * Used by Ed25519Verifier to verify WebAuthn varsig signatures
 * 
 * @param {Uint8Array} payload - The payload that was signed
 * @param {Uint8Array} varsigBytes - The varsig-encoded signature
 * @param {Uint8Array} publicKey - Ed25519 public key (32 bytes)
 * @returns {Promise<boolean>}
 */
export async function verifyVarsig(payload, varsigBytes, publicKey) {
  try {
    // Decode varsig from signature.raw
    const decoded = decodeVarsig(varsigBytes)
    
    // The payload was hashed to create the WebAuthn challenge
    const payloadHash = await crypto.subtle.digest('SHA-256', payload)
    const expectedChallenge = new Uint8Array(payloadHash)
    
    // Parse clientDataJSON to get the actual challenge
    const clientDataText = new TextDecoder().decode(decoded.clientDataJSON)
    const clientData = JSON.parse(clientDataText)
    const actualChallenge = base64urlToBytes(clientData.challenge)
    
    // Verify challenge matches
    if (!bytesEqual(expectedChallenge, actualChallenge)) {
      console.error('[ucanto-varsig] Challenge mismatch')
      return false
    }
    
    // Reconstruct the signed data: authenticatorData || SHA-256(clientDataJSON)
    const clientDataHash = await crypto.subtle.digest('SHA-256', decoded.clientDataJSON)
    const signedData = new Uint8Array(
      decoded.authenticatorData.length + clientDataHash.byteLength
    )
    signedData.set(decoded.authenticatorData, 0)
    signedData.set(new Uint8Array(clientDataHash), decoded.authenticatorData.length)
    
    // Verify Ed25519 signature
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      publicKey,
      { name: 'Ed25519' },
      false,
      ['verify']
    )
    
    const valid = await crypto.subtle.verify(
      'Ed25519',
      cryptoKey,
      decoded.signature,
      signedData
    )
    
    if (valid) {
      console.log('✅ [ucanto-varsig] Signature verified successfully')
    } else {
      console.error('❌ [ucanto-varsig] Signature verification failed')
    }
    
    return valid
  } catch (error) {
    console.error('[ucanto-varsig] Verification error:', error)
    return false
  }
}
