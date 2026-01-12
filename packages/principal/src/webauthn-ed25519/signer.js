/**
 * WebAuthn Ed25519 Signer with Varsig Support
 * 
 * This signer uses WebAuthn hardware-backed Ed25519 keys and encodes signatures
 * in varsig format for verification.
 */

import { varint } from 'multiformats'
import * as API from '../ed25519/type.js'
import * as Ed25519Verifier from '../ed25519/verifier.js'
import * as WebAuthnVerifier from './verifier.js'
import { base64pad } from 'multiformats/bases/base64'
import * as Signature from '@ipld/dag-ucan/signature'
import * as Signer from '../signer.js'

export const code = 0x1300 // Same as Ed25519
export const name = 'Ed25519' // WebAuthn Ed25519

/** @type {'EdDSA'} */
export const signatureAlgorithm = 'EdDSA'
export const signatureCode = Signature.EdDSA

// Varsig multicodec for WebAuthn Ed25519
export const VARSIG_WEBAUTHN_ED25519 = 0xd1ed

// Export verifier
export { WebAuthnVerifier as Verifier }

/**
 * Creates a WebAuthn Ed25519 signer from a credential ID and public key
 * 
 * @param {string} credentialId - Base64-encoded WebAuthn credential ID
 * @param {Uint8Array} publicKey - Raw Ed25519 public key (32 bytes)
 * @param {string} did - DID string
 * @returns {WebAuthnEd25519Signer}
 */
export const create = (credentialId, publicKey, did) => {
  return new WebAuthnEd25519Signer(credentialId, publicKey, did)
}

/**
 * WebAuthn Ed25519 Signer
 * Signs using hardware-backed WebAuthn credentials
 */
class WebAuthnEd25519Signer {
  /**
   * @param {string} credentialId 
   * @param {Uint8Array} publicKey 
   * @param {string} didString
   */
  constructor(credentialId, publicKey, didString) {
    this.credentialId = credentialId
    this.publicKey = publicKey
    this._did = didString
  }

  get code() {
    return code
  }

  get signer() {
    return this
  }

  /**
   * Get verifier for this signer
   */
  get verifier() {
    if (!this._verifier) {
      this._verifier = WebAuthnVerifier.create(this.publicKey, this._did)
    }
    return this._verifier
  }

  /** 
   * DID of this principal
   * @returns {API.DID<'key'>}
   */
  did() {
    return /** @type {API.DID<'key'>} */ (this._did)
  }

  /**
   * @returns {API.DID<'key'>}
   */
  toDIDKey() {
    return /** @type {API.DID<'key'>} */ (this._did)
  }

  /**
   * @template {API.DID} ID
   * @param {ID} id
   * @returns {API.Signer<ID>}
   */
  withDID(id) {
    return Signer.withDID(this, id)
  }

  /**
   * Sign payload with WebAuthn hardware credential
   * Returns varsig-encoded signature with EdDSA signature code
   * 
   * @template T
   * @param {API.ByteView<T>} payload
   * @returns {Promise<API.SignatureView<T, typeof Signature.EdDSA>>}
   */
  async sign(payload) {
    // Hash payload to create WebAuthn challenge
    const payloadCopy = new Uint8Array(payload)
    const challengeHash = await crypto.subtle.digest('SHA-256', payloadCopy)
    const challenge = new Uint8Array(challengeHash)

    console.log('🔐 [ucanto-varsig] Requesting WebAuthn signature...')

    // Decode credential ID from base64
    const credIdBytes = Uint8Array.from(atob(this.credentialId), c => c.charCodeAt(0))

    // Get WebAuthn assertion
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [{
          id: credIdBytes,
          type: 'public-key',
          transports: ['internal', 'hybrid']
        }],
        userVerification: 'required',
        timeout: 60000
      }
    })

    if (!assertion) {
      throw new Error('WebAuthn authentication failed')
    }

    // Cast to any to access WebAuthn-specific properties
    const credential = /** @type {any} */ (assertion)
    const response = credential.response

    // Encode as varsig
    const authData = new Uint8Array(response.authenticatorData)
    const clientData = new Uint8Array(response.clientDataJSON)
    const signature = new Uint8Array(response.signature)

    const varsig = encodeVarsig(authData, clientData, signature)

    console.log('✅ [ucanto-varsig] WebAuthn varsig signature obtained:', varsig.length, 'bytes')

    // Wrap in Signature with standard EdDSA code (varsig is transparent to UCAN layer)
    return Signature.create(Signature.EdDSA, varsig)
  }

  /**
   * Verify signature - delegates to verifier
   * 
   * @template T
   * @param {API.ByteView<T>} payload
   * @param {API.Signature<T, typeof Signature.EdDSA>} signature
   * @returns {Promise<boolean>}
   */
  async verify(payload, signature) {
    return this.verifier.verify(payload, signature)
  }

  get signatureAlgorithm() {
    return signatureAlgorithm
  }

  get signatureCode() {
    return signatureCode
  }

  /**
   * Encode signer (public key only, private key is in hardware)
   */
  encode() {
    // Return just the public key with Ed25519 multicodec
    const encoded = new Uint8Array(1 + 32)
    varint.encodeTo(Ed25519Verifier.code, encoded, 0)
    encoded.set(this.publicKey, 1)
    return encoded
  }

  /**
   * Archive for persistence
   * Note: WebAuthn signers cannot be fully serialized as they require browser credentials
   */
  toArchive() {
    const id = this.did()
    return {
      id,
      keys: { 
        [id]: this.encode()
      },
    }
  }
}

/**
 * Encode varsig format
 * Format: [multicodec][authData_len][authData][clientData_len][clientData][signature]
 * @param {Uint8Array} authData
 * @param {Uint8Array} clientData
 * @param {Uint8Array} signature
 * @returns {Uint8Array}
 */
function encodeVarsig(authData, clientData, signature) {
  // Encode lengths as varints
  const authDataLen = encodeVarint(authData.length)
  const clientDataLen = encodeVarint(clientData.length)
  
  // Multicodec for WebAuthn Ed25519 varsig
  const multicodec = encodeVarint(VARSIG_WEBAUTHN_ED25519)
  
  // Calculate total length
  const totalLen = multicodec.length + authDataLen.length + authData.length + 
                   clientDataLen.length + clientData.length + signature.length
  
  // Concatenate
  const result = new Uint8Array(totalLen)
  let offset = 0
  
  result.set(multicodec, offset)
  offset += multicodec.length
  
  result.set(authDataLen, offset)
  offset += authDataLen.length
  
  result.set(authData, offset)
  offset += authData.length
  
  result.set(clientDataLen, offset)
  offset += clientDataLen.length
  
  result.set(clientData, offset)
  offset += clientData.length
  
  result.set(signature, offset)
  
  return result
}

/**
 * Simple varint encoder
 * @param {number} value
 * @returns {Uint8Array}
 */
function encodeVarint(value) {
  const bytes = []
  while (value >= 0x80) {
    bytes.push((value & 0x7f) | 0x80)
    value >>>= 7
  }
  bytes.push(value & 0x7f)
  return new Uint8Array(bytes)
}
