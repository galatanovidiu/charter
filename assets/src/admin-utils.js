import { Button, Modal } from '@wordpress/components';
import { useState } from '@wordpress/element';
import { __ } from '@wordpress/i18n';

export function readData(id) {
	const element = document.getElementById(id);
	if (!element) {
		return {};
	}

	try {
		return JSON.parse(element.textContent || '{}');
	} catch (error) {
		return {};
	}
}

export function PostForm({
	action,
	extraFields = {},
	children,
	className = '',
}) {
	if (!action) {
		return null;
	}

	return (
		<form method="post" action={action.url} className={className}>
			{Object.entries({ ...action.fields, ...extraFields }).map(
				([name, value]) => (
					<input key={name} type="hidden" name={name} value={value} />
				)
			)}
			{children}
		</form>
	);
}

export function ConfirmAction({
	action,
	label,
	title,
	description,
	confirmLabel = label,
	variant = 'secondary',
	isDestructive = false,
	extraFields = { confirm_action: '1' },
	disabled = false,
}) {
	const [isOpen, setOpen] = useState(false);
	if (!action) {
		return null;
	}

	return (
		<>
			<Button
				variant={variant}
				isDestructive={isDestructive}
				disabled={disabled}
				accessibleWhenDisabled
				onClick={() => setOpen(true)}
			>
				{label}
			</Button>
			{isOpen && (
				<Modal title={title} onRequestClose={() => setOpen(false)}>
					<p>{description}</p>
					<div className="charter-modal-actions">
						<Button
							variant="tertiary"
							onClick={() => setOpen(false)}
						>
							{__('Cancel', 'charter')}
						</Button>
						<PostForm action={action} extraFields={extraFields}>
							<Button
								type="submit"
								variant={
									isDestructive ? 'secondary' : 'primary'
								}
								isDestructive={isDestructive}
							>
								{confirmLabel}
							</Button>
						</PostForm>
					</div>
				</Modal>
			)}
		</>
	);
}

export function PageHeader({ eyebrow, title, description, status, actions }) {
	return (
		<header className="charter-page-header">
			<div>
				{eyebrow && <p className="charter-eyebrow">{eyebrow}</p>}
				<div className="charter-title-line">
					<h1>{title}</h1>
					{status}
				</div>
				{description && (
					<p className="charter-page-description">{description}</p>
				)}
			</div>
			{actions && <div className="charter-header-actions">{actions}</div>}
		</header>
	);
}

export function StatusBadge({ status = 'neutral', children }) {
	return (
		<span className={`charter-status charter-status--${status}`}>
			{children}
		</span>
	);
}

export function EmptyState({ title, description, children }) {
	return (
		<div className="charter-empty-state">
			<div className="charter-empty-mark" aria-hidden="true" />
			<h3>{title}</h3>
			{description && <p>{description}</p>}
			{children}
		</div>
	);
}

export function Pagination({ pagination, previousLabel, nextLabel }) {
	if (!pagination || pagination.pages <= 1) {
		return null;
	}

	return (
		<nav
			className="charter-pagination"
			aria-label={__('Pagination', 'charter')}
		>
			<Button
				variant="secondary"
				href={pagination.previous || undefined}
				disabled={!pagination.previous}
				accessibleWhenDisabled
			>
				{previousLabel}
			</Button>
			<span>{sprintfPage(pagination.page, pagination.pages)}</span>
			<Button
				variant="secondary"
				href={pagination.next || undefined}
				disabled={!pagination.next}
				accessibleWhenDisabled
			>
				{nextLabel}
			</Button>
		</nav>
	);
}

function sprintfPage(page, pages) {
	return `${__('Page', 'charter')} ${page} ${__('of', 'charter')} ${pages}`;
}

export function TechnicalDetails({
	children,
	label = __('Technical details', 'charter'),
}) {
	return (
		<details className="charter-technical-details">
			<summary>{label}</summary>
			<div>{children}</div>
		</details>
	);
}

export function humanizeToken(value) {
	const label = String(value || '')
		.replace(/[_-]+/g, ' ')
		.replace(/\b\w/g, (character) => character.toUpperCase());

	return label
		.replace(/\bOauth\b/g, 'OAuth')
		.replace(/\bCimd\b/g, 'CIMD')
		.replace(/\bPkce\b/g, 'PKCE')
		.replace(/\bWordpress\b/g, 'WordPress');
}

export function scopeLabel(scope) {
	const labels = {
		'wordpress:access': __('Use WordPress as you', 'charter'),
		'abilities-catalog:access': __('Use the Abilities Catalog', 'charter'),
		offline_access: __('Continue access after you leave', 'charter'),
	};

	return labels[scope] || scope;
}
