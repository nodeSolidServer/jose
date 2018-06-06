const path = require('path')

module.exports = {
  mode: 'production',
  entry: [
    './lib/index.js'
  ],
  output: {
    path: path.join(__dirname, '/dist/'),
    filename: 'jose.min.js',
    library: 'JOSE',
    libraryTarget: 'var'
  },
  module: {
  },
  externals: {
    'text-encoding': 'TextEncoder',
    '@trust/webcrypto': 'crypto'
  },
  devtool: 'source-map'
}
