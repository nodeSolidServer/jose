const crypto = require('isomorphic-webcrypto')

const alg = { name: 'ECDSA', hash: { name: 'SHA-256' }, namedCurve: "P-256" }

const EcdsaPublicJwk = {
  "crv": "P-256",
  "ext": true,
  "key_ops": [
      "verify"
  ],
  "kty": "EC",
  "x": "uOn1dXfOejFDxl82ou1BqcWJj817HIs2BJbwkIdf0v4",
  "y": "tA_wAZevVIITzb0UdivivtcOWEkiK6I3GxHsA_b8e70"
}

const EcdsaPrivateJwk = {
  "crv": "P-256",
  "d": "HDlY69G2D9u_mmu3SbnLQqJW57opS84s2OWkE5uq9io",
  "ext": true,
  "key_ops": [
      "sign"
  ],
  "kty": "EC",
  "x": "uOn1dXfOejFDxl82ou1BqcWJj817HIs2BJbwkIdf0v4",
  "y": "tA_wAZevVIITzb0UdivivtcOWEkiK6I3GxHsA_b8e70"
}

async function getPublicKey () {
  return await crypto.subtle.importKey('jwk', EcdsaPublicJwk, alg, true, ['verify'])
}

async function getPrivateKey () {
  return await crypto.subtle.importKey('jwk', EcdsaPrivateJwk, alg, true, ['sign'])
}

/**
 * Export
 */
module.exports = {
  EcdsaPrivateJwk,
  EcdsaPublicJwk,
  getPublicKey,
  getPrivateKey,
}

/**
 * We produced the testing keys and signatures for ECDSASpec.js
 * in Chromium Version 103.0.5060.134 (Official Build) Arch Linux (64-bit)
 * with the following functions
 * with typescript types stripped off:
 * (may contain mistakes)
 *
// algorithm
const alg: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' }}

// generate keys
const generateKeyPair = async (alg: EcKeyGenParams): Promise<CryptoKey> => await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])

// export keys as jwk
const exportPublicKey = async (keyPair: CryptoKey): Promise<JsonWebKey> => await crypto.subtle.exportKey('jwk', keyPair.publicKey)

const exportPrivateKey = async (keyPair: CryptoKey): Promise<JsonWebKey> => await crypto.subtle.exportKey('jwk', keyPair.privateKey)

// import jwk keys
const importPublicKey = async (publicKey: JsonWebKey, alg: EcKeyImportParams): Promise<CryptoKey> => await crypto.subtle.importKey('jwk', publicKey, alg, true, ['verify'])

const importPrivateKey = async (privateKey: JsonWebKey, alg: EcKeyImportParams): Promise<CryptoKey> => await crypto.subtle.importKey('jwk', privateKey, alg, true, ['sign'])

// sign text data
const sign = async (alg: EcKeyParams, privateKey: CryptoKey, data: string): Promise<ArrayBuffer> => {
  const rawData = new TextEncoder().encode(data)
  const rawSignature = await crypto.subtle.sign(alg, privateKey, rawData)
  return rawSignature
}

// produce string signature
const getStringSignature = (signature: ArrayBuffer): string => btoa(String.fromCharCode(...new Uint8Array(signature)))

const getUint8ArraySignature = (signature: ArrayBuffer): Uint8Array => new Uint8Array(signature)
 */
