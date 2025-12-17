const crypto = require('isomorphic-webcrypto')
const JWA = require('../src/jose/JWA')

let privateKey, publicKey

console.log('Testing ES256 support in @solid/jose library...')

crypto.subtle

  // use webcrypto to generate an ECDSA keypair
  .generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
      hash: {
        name: 'SHA-256'
      }
    },
    true,
    ['sign', 'verify']
  )

  // use key with JWA to create a signature
  .then(keypair => {
    privateKey = keypair.privateKey
    publicKey = keypair.publicKey
    
    console.log('✅ ES256 key pair generated successfully')
    
    return JWA.sign('ES256', privateKey, 'header.payload')
  })

  // verify the signature
  .then(signature => {
    console.log('✅ ES256 signature created:', signature.substring(0, 20) + '...')
    
    return Promise.all([
      Promise.resolve(signature),
      JWA.verify('ES256', publicKey, signature, 'header.payload'),
      JWA.verify('ES256', publicKey, signature, 'wrong'),
    ])
  })

  // look at the output
  .then(result => {
    console.log('✅ ES256 verify results:')
    console.log('  Signature:', result[0].substring(0, 20) + '...')
    console.log('  Valid signature verified:', result[1])
    console.log('  Invalid signature verified:', result[2])
    
    if (result[1] === true && result[2] === false) {
      console.log('🎉 ES256 is FULLY FUNCTIONAL in @solid/jose!')
    }
  })

  // look at any errors
  .catch(error => {
    console.error('❌ ES256 test failed:', error.message)
    if (error.message.includes('normalizedAlgorithm.importKey')) {
      console.error('❌ This is the importKey error we were seeing!')
    }
  })