'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')

/**
 * Assertions
 */
chai.should()
chai.use(chaiAsPromised)
let expect = chai.expect

/**
 * Code under test
 */
const Index = require('../src/')

/**
 * Tests
 */
describe('Index', () => {
  it('exports crypto', () => {
    return Object.keys(Index.crypto).should.deep.equal(['subtle'])
  })
})
