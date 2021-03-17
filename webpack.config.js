const path = require('path');

const webpack      = require('webpack');
const TerserPlugin = require("terser-webpack-plugin");

// follow https://webpack.js.org/configuration/mode/#mode-production except for env var
module.exports = {
  mode: 'none',
  entry: './lib/paseto.browser.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'paseto.bundle.js',
    pathinfo: false
  },
  plugins: [
    new webpack.IgnorePlugin({resourceRegExp: /(node|symmetric|private)$/}),
    // follow https://github.com/webpack/webpack/blob/c18b3c53e5c3e05ace0bff03a0b1469a2b85f1b6/lib/config/defaults.js#L927-L933
    new TerserPlugin({ terserOptions: { compress: { passes: 2 } } }),
    new webpack.DefinePlugin({ 'process.env.NODE_ENV': JSON.stringify('development') }),
    new webpack.optimize.ModuleConcatenationPlugin(),
    new webpack.NoEmitOnErrorsPlugin()
  ],
  resolve: {
    fallback: {
      crypto: false,
      path: false
    },
  },
  performance: {
    hints: 'warning'
  },
  optimization: {
    moduleIds: 'deterministic',
    chunkIds: 'deterministic',
    mangleExports: 'deterministic',
    nodeEnv: 'development',
    flagIncludedChunks: true,
    //occurrenceOrder: true,
    concatenateModules: true,
    splitChunks: {
      hidePathInfo: true,
      minSize: 30000,
      maxAsyncRequests: 5,
      maxInitialRequests: 3,
    },
    emitOnErrors: false,
    checkWasmTypes: true,
    minimize: true
  }
};
