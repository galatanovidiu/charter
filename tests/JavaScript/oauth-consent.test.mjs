import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const script = readFileSync(
	new URL('../../assets/js/oauth-consent.js', import.meta.url),
	'utf8'
);

function consentPage() {
	const scheduled = [];
	const status = { hidden: true };
	const buttons = [{ disabled: false }, { disabled: false }];
	const listeners = new Map();
	const attributes = new Map();
	const form = {
		addEventListener(type, listener) {
			listeners.set(type, listener);
		},
		querySelector(selector) {
			return selector === '[data-charter-oauth-status]' ? status : null;
		},
		querySelectorAll(selector) {
			return selector === 'button[type="submit"]' ? buttons : [];
		},
		setAttribute(name, value) {
			attributes.set(name, value);
		},
	};

	vm.runInNewContext(script, {
		document: {
			querySelector(selector) {
				return selector === '[data-charter-oauth-consent]'
					? form
					: null;
			},
		},
		window: {
			setTimeout(callback) {
				scheduled.push(callback);
			},
		},
	});

	return { attributes, buttons, listeners, scheduled, status };
}

test('locks consent after the first submission without dropping its decision', () => {
	const page = consentPage();
	const submit = page.listeners.get('submit');
	let firstPrevented = false;
	let secondPrevented = false;

	submit({
		preventDefault() {
			firstPrevented = true;
		},
	});

	assert.equal(firstPrevented, false);
	assert.equal(page.attributes.get('aria-busy'), 'true');
	assert.equal(page.status.hidden, false);
	assert.deepEqual(page.buttons, [{ disabled: false }, { disabled: false }]);

	submit({
		preventDefault() {
			secondPrevented = true;
		},
	});

	assert.equal(secondPrevented, true);
	assert.equal(page.scheduled.length, 1);

	page.scheduled[0]();
	assert.deepEqual(page.buttons, [{ disabled: true }, { disabled: true }]);
});
