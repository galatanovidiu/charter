'use strict';

const fs = require( 'node:fs' );
const path = require( 'node:path' );

const projectRoot = path.resolve( __dirname, '..' );
const files = [
	'node_modules/@wordpress/env/lib/download-sources.js',
	'node_modules/@wordpress/env/lib/runtime/docker/download-wp-phpunit.js',
];
const original = "const SimpleGit = require( 'simple-git' );";
const patched = "const { simpleGit: SimpleGit } = require( 'simple-git' );";

for ( const relativePath of files ) {
	const filePath = path.join( projectRoot, relativePath );
	const contents = fs.readFileSync( filePath, 'utf8' );
	if ( contents.includes( patched ) ) {
		continue;
	}
	if ( ! contents.includes( original ) ) {
		throw new Error( `Unsupported @wordpress/env simple-git import in ${ relativePath }` );
	}
	fs.writeFileSync( filePath, contents.replace( original, patched ), 'utf8' );
}
