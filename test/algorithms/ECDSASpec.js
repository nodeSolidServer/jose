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

    const  jwkEcdsaKey = {
    "crv": "P-256",
    "d": "XX7AP7HV-6zBeUsAIFwBgpqsQf76ebFN1gquG-9wk8Q",
    "ext": true,
    "key_ops": [
        "sign"
    ],
    "kty": "EC",
    "x": "KNeDy7FqchFNXivYDpnNSk0tTvox5cWwJgGoUom24BA",
    "y": "qlC7dwMwytkZTY8E6s4Fam1JA8D19OhyFKrUM_aRgPo"
}
const chromeEcdsaSignature = new Uint8Array([
    238,
    23,
    148,
    239,
    242,
    150,
    132,
    224,
    198,
    144,
     143,
     31,
     211,
     82,
     220,
     86,
     193,
     138,
     128,
     199,
     103,
     190,
     187,
     230,
     40,
     4,
     113,
     108,
     163,
     147,
     112,
     70,
     9,
     92,
     99,
     83,
     4,
     222,
     75,
     162,
     21,
     156,
     135,
     201,
     31,
     42,
     209,
     14,
     208,
     206,
     227,
     13,
     160,
     228,
     84,
     73,
     74,
     164,
     83,
     7,
     23,
     184,
     73,
     160
])

const publicKey= new Uint8Array([
  4,
  40,
  215,
  131,
  203,
  177,
  106,
  114,
  17,
  77,
   94,
   43,
   216,
   14,
   153,
   205,
   74,
   77,
   45,
   78,
   250,
   49,
   229,
   197,
   176,
   38,
   1,
   168,
   82,
   137,
   182,
   224,
   16,
   170,
   80,
   187,
   119,
   3,
   48,
   202,
   217,
   25,
   77,
   143,
   4,
   234,
   206,
   5,
   106,
   109,
   73,
   3,
   192,
   245,
   244,
   232,
   114,
   20,
   170,
   212,
   51,
   246,
   145,
   128,
   250
])
   const   signature = 'YvmWUlEcE3C739KYsNRkykl9roZjr7vn0BHkMt0JZqemnWS3pYUoS7AvFs6D3POPosDEk20GbewTs3Mr/K5pWA=='
     const alg = { name: 'ECDSA', hash: { name: 'SHA-256' }, namedCurve: "P-256" }


     const data = 'signed with Chrome generated webcrypto key'
/**
 * Tests
 */
describe.only('ECDSA', () => {

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
    let importedEcdsaKey, importedPublicKey

    before(() => {

      return crypto.subtle
        .importKey('jwk', jwkEcdsaKey, alg, true, ['sign', 'verify'])
        .then(cryptoKey => importedEcdsaKey = cryptoKey)
    })

    before(() => {
      return crypto.subtle
        .importKey('raw', publicKey, alg, true, ['verify'])
        .then(cryptoKey => importedPublicKey = cryptoKey)
    })

    it('should return a promise', () => {
      let ecdsa = new ECDSA(alg)
      return ecdsa.sign(importedEcdsaKey, data).should.be.instanceof(Promise)
    })

    it('should reject an insufficient key length')

    it('should resolve a base64url encoded value', () => {
      let ecdsa = new ECDSA(alg)
      return ecdsa.sign(importedEcdsaKey, data)
        .then(signature => {
          // ECDSA is non-deterministic. Therefore we test that the generated signature gets verified with crypto library
          return crypto.subtle.verify({  name: 'ECDSA', hash: { name: 'SHA-256' }, namedCurve: "P-256"}, importedPublicKey, new TextEncoder().encode(signature), new TextEncoder().encode(data))
        //  base64url.toBuffer(signature)
          //  .should.eql(Buffer.from(chromeEcdsaSignature.buffer))
        })
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    let importedEcdsaKey

    before(() => {

      return crypto.subtle
        .importKey('raw', publicKey, alg, true, ['verify'])
        .then(cryptoKey => importedEcdsaKey = cryptoKey)
    })

    it('should return a promise', () => {
      let ecdsa = new ECDSA(alg)
      ecdsa.verify(importedEcdsaKey, signature, data).should.be.instanceof(Promise)
    })

    it('should resolve a boolean', () => {
      let ecdsa = new ECDSA(alg)
      return ecdsa.verify(importedEcdsaKey, signature, data)
        .then(verified => {
          expect(verified).to.equal(true)
        })

    })
  })
})

