import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const script = readFileSync(
	new URL('../../assets/js/oauth-consent.js', import.meta.url),
	'utf8'
);

function consentPage() {
	const status = { hidden: true };
	const buttons = [
		{ disabled: false, name: 'decision', value: 'approve' },
		{ disabled: false, name: 'decision', value: 'deny' },
	];
	const appended = [];
	const listeners = new Map();
	const attributes = new Map();
	const form = {
		addEventListener(type, listener) {
			listeners.set(type, listener);
		},
		appendChild(element) {
			appended.push(element);
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
			createElement() {
				return {};
			},
			querySelector(selector) {
				return selector === '[data-charter-oauth-consent]'
					? form
					: null;
			},
		},
		window: {},
	});

	return { appended, attributes, buttons, listeners, status };
}

test('locks consent after the first submission without dropping its decision', () => {
	const page = consentPage();
	const submit = page.listeners.get('submit');
	let firstPrevented = false;
	let secondPrevented = false;

	submit({
		submitter: page.buttons[0],
		preventDefault() {
			firstPrevented = true;
		},
	});

	assert.equal(firstPrevented, false);
	assert.equal(page.attributes.get('aria-busy'), 'true');
	assert.equal(page.status.hidden, false);
	assert.deepEqual(page.appended, [
		{ type: 'hidden', name: 'decision', value: 'approve' },
	]);
	assert.deepEqual(page.buttons, [
		{ disabled: true, name: 'decision', value: 'approve' },
		{ disabled: true, name: 'decision', value: 'deny' },
	]);

	submit({
		submitter: page.buttons[0],
		preventDefault() {
			secondPrevented = true;
		},
	});

	assert.equal(secondPrevented, true);
	assert.equal(page.appended.length, 1);
});
