'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const ECDSA = require('../../src/algorithms/ECDSA')
const {TextEncoder} = require('@sinonjs/text-encoding')
const crypto = require('isomorphic-webcrypto')
const base64url = require('base64url')
const { getPublicKey, getPrivateKey } = require('../keys/ES256')
const { should } = require('chai')

/**
 * Reused test constants
 */
const alg = { name: 'ECDSA', hash: { name: 'SHA-256' }, namedCurve: "P-256" }

const data = 'signed with Chrome generated webcrypto key'

/**
 * Tests
 */
describe('ECDSA', () => {

  /**
   * constructor
   */
  describe('constructor', () => {
    it('should set params', () => {
      let alg = { name: 'ECDSA' }
      let ecdsa = new ECDSA(alg)
      ecdsa.params.should.equal(alg)
    })
  })

  /**
   * sign
   */
  describe('sign', () => {
    let importedEcdsaPrivateKey, importedEcdsaPublicKey

    before(async () => {
      importedEcdsaPrivateKey = await getPrivateKey()
      importedEcdsaPublicKey = await getPublicKey()
    })

    it('should return a promise', () => {
      let ecdsa = new ECDSA(alg)
      return ecdsa.sign(importedEcdsaPrivateKey, data).should.be.instanceof(Promise)
    })

    it('should reject an insufficient key length')

    it('should resolve a base64url encoded value and verification should pass', async () => {
      const ecdsa = new ECDSA(alg)
      const signature = await ecdsa.sign(importedEcdsaPrivateKey, data)

      // this will fail if signature is anything but base64 string
      expect(base64url(base64url.toBuffer(signature))).to.equal(signature)

      // ECDSA is non-deterministic. Therefore we test that the generated signature gets verified with crypto library
      const verified = await crypto.subtle.verify(
        {
          name: 'ECDSA',
          hash: { name: 'SHA-256' },
          namedCurve: "P-256"
        },
        importedEcdsaPublicKey,
        base64url.toBuffer(signature),
        new TextEncoder().encode(data)
      )

      verified.should.eql(true)
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    let importedEcdsaPublicKey, signature

    before(async () => {
      /**
       * This signature was produced in Chromium
       * deails can be found in comments of ../keys/ES256.js
       */
      signature = 'AUNkOnr//z999flIoTMebaf5EQC56WVQizK3GXW/u4EOQBvs9CtvfgWi0pQ3bi0k8p357ajtNvN/dJ1Vr8gbYg=='

      importedEcdsaPublicKey = await getPublicKey()
    })

    it('should return a promise', () => {
      let ecdsa = new ECDSA(alg)
      ecdsa.verify(importedEcdsaPublicKey, signature, data).should.be.instanceof(Promise)
    })

    it('should resolve to true', async () => {
      const ecdsa = new ECDSA(alg)
      const verified = await ecdsa.verify(importedEcdsaPublicKey, signature, data)
      expect(verified).to.equal(true)
    })
  })

  /**
   * importKey
   */
  describe('importKey', () => {
    let exampleJwkPublicKey

    before(() => {
      exampleJwkPublicKey = {
        crv: 'P-256',
        kty: 'EC',
        x: '-c0_z0ly3xRDR0XQuvIirfgal59hq7BzF9ObdUXrgmI',
        y: '_7QdnDYKrkrkYaCqZko0ebDQ1L1RpHLtzg8YwdT79n8',
        alg: 'ES256'
      }
    })

    it('should successfully import public jwk key', async () => {
      const ecdsa = new ECDSA(alg)
      const key = await ecdsa.importKey(exampleJwkPublicKey)
      key.cryptoKey.constructor.name.should.equal('CryptoKey')
    })
  })
})

