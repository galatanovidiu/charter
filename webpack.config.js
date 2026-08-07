const path = require('path');
const DependencyExtractionWebpackPlugin = require('@wordpress/dependency-extraction-webpack-plugin');

module.exports = {
	entry: {
		'site-admin': './assets/src/site-admin.js',
		'connected-apps': './assets/src/connected-apps.js',
		'network-admin': './assets/src/network-admin.js',
	},
	output: {
		filename: '[name].js',
		path: path.resolve(__dirname, 'assets/admin'),
		clean: true,
	},
	module: {
		rules: [
			{
				test: /\.js$/,
				exclude: /node_modules/,
				use: {
					loader: 'babel-loader',
					options: {
						presets: [
							['@babel/preset-env', { modules: false }],
							['@babel/preset-react', { runtime: 'automatic' }],
						],
					},
				},
			},
		],
	},
	plugins: [new DependencyExtractionWebpackPlugin()],
	optimization: {
		splitChunks: false,
		runtimeChunk: false,
	},
};
