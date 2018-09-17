const path = require("path");
var nodeExternals = require("webpack-node-externals");
// Variables
const outPath = path.resolve(__dirname, "dist");

const serverConfig = {
  context: __dirname,
  target: "node",
  entry: path.resolve(__dirname, "app.js"),
  output: {
    path: outPath,
    filename: "app.bundle.js"
  },
  mode: process.env.NODE_ENV || "development",
  externals: [nodeExternals()],
  module: {
    rules: [
      {
        test: /\.(js)$/,
        exclude: /node_modules/
      }
    ]
  }
};

module.exports = [serverConfig];
