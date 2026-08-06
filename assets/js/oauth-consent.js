(function () {
	'use strict';

	const form = document.querySelector('[data-charter-oauth-consent]');
	if (!form) {
		return;
	}

	const buttons = form.querySelectorAll('button[type="submit"]');
	const status = form.querySelector('[data-charter-oauth-status]');
	let submitted = false;

	form.addEventListener('submit', function (event) {
		if (submitted) {
			event.preventDefault();
			return;
		}

		submitted = true;
		form.setAttribute('aria-busy', 'true');
		if (status) {
			status.hidden = false;
		}

		window.setTimeout(function () {
			buttons.forEach(function (button) {
				button.disabled = true;
			});
		}, 0);
	});
})();
