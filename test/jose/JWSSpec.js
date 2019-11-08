'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const { expect } = chai

/**
 * Assertions
 */
chai.should()
// let expect = chai.expect

/**
 * Code under test
 */
// const crypto = require('isomorphic-webcrypto')
const JWS = require('../../src/jose/JWS')
const { DataError } = require('../../src/errors')
const { getPublicKey, getPrivateKey } = require('../keys')

/**
 * Tests
 */
describe('JWS', () => {

  /**
   * sign
   */
  describe('sign', () => {
    describe('Compact Serialization', () => {
      let token, compact

      before(async () => {
        token = {
          serialization: 'compact',
          header: { alg: 'RS256', kid: 'r4nd0mbyt3s' },
          payload: { iss: 'https://forge.anvil.io' },
          key: await getPrivateKey()
        }

        compact = 'eyJhbGciOiJSUzI1NiIsImtpZCI6InI0bmQwbWJ5dDNzIn0.eyJpc3MiOiJodHRwczovL2ZvcmdlLmFudmlsLmlvIn0.FMer-lRR4Q4BVivMc9sl-jF3c-QWEenlH2pcW9oXTsiPRSEzc7lgPEryuXTimoToSKwWFgVpnjXKnmBaTaPVLpuRUMwGUeIUdQu0bQC-XEo-TKlwlqtUgelQcF2viEQwxU04UQaXWBh9ZDTIOutfXcjyhEPiMfCFLxT_aotR0zipmAi825lF1qBmxKrCv4c_9_46ACuaeuET6t0XvcAMDf3fjkEdw_0KPN2wnAlp2AwPP05D8Nwn8NqDAlljdN7bjnO99uJvhNWbvZgBYfhNXkMeDVJcukv0j3Cz6LCgedbXdX0rzJv_4qkO6l-LU9QeK1s0kwHfRUIWoa0TLJ4FtQ'
      })

      it('should return a promise', () => {
        return JWS.sign(token).should.be.fulfilled
      })

      it('should resolve a signed JWT', () => {
        return JWS.sign(token).should.eventually.equal(compact)
      })
    })

    describe('JSON Serialization', () => {
      it('should return a promise')
      it('should resolve a string')
      it('should resolve a signed JWT')
    })

    describe('Flattened JSON Serialization', () => {
      it('should return a promise')
      it('should resolve a string')
      it('should resolve a signed JWT')
    })

    describe('Unsupported Serialization', () => {
      let token

      before(async () => {
        token = {
          serialization: 'unsupported',
          header: { alg: 'RS256', kid: 'r4nd0mbyt3s' },
          payload: { iss: 'https://forge.anvil.io' },
          key: await getPrivateKey()
        }
      })

      it('should reject with a DataError', async () => {
        let dataError

        try {
          await JWS.sign(token)
        } catch (error) {
          dataError = error
        }

        expect(dataError instanceof DataError).to.be.true
      })
    })
  })

  /**
   * verify
   */
  describe('verify', () => {
    describe('Compact Serialization', () => {
      let jwt, signature

      before(async () => {
        signature = 'FMer-lRR4Q4BVivMc9sl-jF3c-QWEenlH2pcW9oXTsiPRSEzc7lgPEryuXTimoToSKwWFgVpnjXKnmBaTaPVLpuRUMwGUeIUdQu0bQC-XEo-TKlwlqtUgelQcF2viEQwxU04UQaXWBh9ZDTIOutfXcjyhEPiMfCFLxT_aotR0zipmAi825lF1qBmxKrCv4c_9_46ACuaeuET6t0XvcAMDf3fjkEdw_0KPN2wnAlp2AwPP05D8Nwn8NqDAlljdN7bjnO99uJvhNWbvZgBYfhNXkMeDVJcukv0j3Cz6LCgedbXdX0rzJv_4qkO6l-LU9QeK1s0kwHfRUIWoa0TLJ4FtQ'
        jwt = {
          header: { alg: 'RS256' },
          signature,
          segments: [
            'eyJhbGciOiJSUzI1NiIsImtpZCI6InI0bmQwbWJ5dDNzIn0',
            'eyJpc3MiOiJodHRwczovL2ZvcmdlLmFudmlsLmlvIn0',
            signature
          ],
          key: await getPublicKey()
        }
      })

      it('should resolve with a boolean', async () => {
        expect(await JWS.verify(jwt)).to.be.true
      })

      it('should set JWT verified property', () => {
        return JWS.verify(jwt).then(verified => {
          jwt.verified.should.equal(true)
        })
      })
    })

    describe('multiple signature serialization', () => {
      it('should return a promise')
      it('should resolve the JWT')
      it('should set JWT verified property')
    })

    describe('missing signature(s)', () => {
      let jwt

      before(async () => {
        jwt = {
          header: { alg: 'RS256' },
          key: await getPublicKey()
        }
      })

      it('should reject a DataError', async () => {
        let dataError

        try {
          await JWS.verify(jwt)
        } catch (error) {
          dataError = error
        }

        expect(dataError instanceof DataError).to.be.true
      })
    })
  })
})
