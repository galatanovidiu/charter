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

		const submitter = event.submitter;
		if (
			!submitter ||
			submitter.name !== 'decision' ||
			!['approve', 'deny'].includes(submitter.value)
		) {
			event.preventDefault();
			return;
		}

		const decision = document.createElement('input');
		decision.type = 'hidden';
		decision.name = submitter.name;
		decision.value = submitter.value;
		form.appendChild(decision);

		submitted = true;
		form.setAttribute('aria-busy', 'true');
		if (status) {
			status.hidden = false;
		}

		buttons.forEach(function (button) {
			button.disabled = true;
		});
	});
})();
