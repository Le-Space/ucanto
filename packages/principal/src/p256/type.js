import * as Signature from '@ipld/dag-ucan/signature'

export * from '@le-space/ucanto-interface'

/**
 * Integer corresponding to ES256 byteprefix of the VarSig.
 * @typedef {import('@le-space/ucanto-interface').MulticodecCode<typeof Signature.ES256, 'ES256'>} SigAlg
 */

/**
 * Name corresponding to ES256 algorithm.
 * @typedef {'ES256'} Name
 */

/**
 * P-256 Signer interface
 * @typedef {import('@le-space/ucanto-interface').SignerKey<SigAlg> & {
 *   readonly signatureAlgorithm: Name
 *   readonly code: import('@le-space/ucanto-interface').MulticodecCode<0x1301, 'p256-private-key'>
 *   readonly signer: P256Signer
 *   readonly verifier: P256Verifier
 *   encode(): import('@le-space/ucanto-interface').ByteView<P256Signer & CryptoKeyPair>
 *   toArchive(): {
 *     id: import('@le-space/ucanto-interface').DIDKey
 *     keys: { [Key: import('@le-space/ucanto-interface').DIDKey]: import('@le-space/ucanto-interface').ByteView<import('@le-space/ucanto-interface').SignerKey<SigAlg> & CryptoKey> }
 *   }
 * }} P256Signer
 */

/**
 * P-256 Verifier interface
 * @typedef {import('@le-space/ucanto-interface').VerifierKey<SigAlg> & {
 *   readonly code: import('@le-space/ucanto-interface').MulticodecCode<0x1200, 'p256-public-key'>
 *   readonly signatureCode: SigAlg
 *   readonly signatureAlgorithm: Name
 * }} P256Verifier
 */
