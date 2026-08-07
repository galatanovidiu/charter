import { Card, CardBody, PanelBody } from '@wordpress/components';
import { createRoot } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import {
	ConfirmAction,
	EmptyState,
	PageHeader,
	StatusBadge,
	TechnicalDetails,
	readData,
	scopeLabel,
} from './admin-utils';

const data = readData('charter-connected-apps-data');

function ConnectedApps() {
	return (
		<div className="charter-admin-app charter-connected-apps">
			<PageHeader
				eyebrow={__('Your account', 'charter')}
				title={__('Connected Apps', 'charter')}
				description={__(
					'Review applications that can act through OAuth as your WordPress account. Your normal WordPress permissions still apply.',
					'charter'
				)}
				status={
					data.active.length > 0 ? (
						<StatusBadge status="info">
							{sprintf(
								_n(
									'%d connected',
									'%d connected',
									data.active.length,
									'charter'
								),
								data.active.length
							)}
						</StatusBadge>
					) : null
				}
			/>

			{data.active.length === 0 ? (
				<EmptyState
					title={__('No applications are connected', 'charter')}
					description={__(
						'When you authorize an application to use this site, it will appear here.',
						'charter'
					)}
				/>
			) : (
				<section aria-labelledby="charter-active-apps-title">
					<h2
						id="charter-active-apps-title"
						className="charter-visually-hidden"
					>
						{__('Active applications', 'charter')}
					</h2>
					<div className="charter-app-card-list">
						{data.active.map((grant) => (
							<ApplicationCard key={grant.id} grant={grant} />
						))}
					</div>
				</section>
			)}

			{data.history.length > 0 && <History />}
		</div>
	);
}

function ApplicationCard({ grant }) {
	return (
		<Card className="charter-app-card">
			<CardBody>
				<div className="charter-app-card-header">
					<div className="charter-app-identity">
						<span
							className="charter-app-monogram"
							aria-hidden="true"
						>
							{monogram(grant.application)}
						</span>
						<div>
							<h3>{grant.application}</h3>
							<p>
								{__('Last used', 'charter')} {grant.lastUsedAt}
							</p>
						</div>
					</div>
					<StatusBadge status="healthy">
						{__('Active', 'charter')}
					</StatusBadge>
				</div>
				<div className="charter-permissions">
					<h4>{__('This application can:', 'charter')}</h4>
					<ul>
						{grant.scopes.map((scope) => (
							<li key={scope}>{scopeLabel(scope)}</li>
						))}
						{grant.continuingAccess && (
							<li>
								{__(
									'Continue accessing this site until you disconnect it',
									'charter'
								)}
							</li>
						)}
					</ul>
				</div>
				<TechnicalDetails>
					<dl className="charter-key-values">
						<div>
							<dt>{__('Client ID', 'charter')}</dt>
							<dd>
								<code>{grant.clientId}</code>
							</dd>
						</div>
						<div>
							<dt>{__('Resource', 'charter')}</dt>
							<dd>
								<code>{grant.resource}</code>
							</dd>
						</div>
						<div>
							<dt>{__('Scopes', 'charter')}</dt>
							<dd>
								<code>{grant.scopes.join(' ')}</code>
							</dd>
						</div>
						<div>
							<dt>{__('Authorized', 'charter')}</dt>
							<dd>{grant.authorizedAt}</dd>
						</div>
					</dl>
				</TechnicalDetails>
				<div className="charter-app-card-actions">
					<ConfirmAction
						action={grant.action}
						label={__('Disconnect', 'charter')}
						title={sprintf(
							__('Disconnect %s?', 'charter'),
							grant.application
						)}
						description={__(
							'The application will immediately lose active and continuing access granted through this authorization.',
							'charter'
						)}
						confirmLabel={__('Disconnect application', 'charter')}
						isDestructive
						extraFields={{}}
					/>
				</div>
			</CardBody>
		</Card>
	);
}

function History() {
	return (
		<section
			className="charter-history"
			aria-labelledby="charter-history-title"
		>
			<PanelBody
				title={__('Recently disconnected', 'charter')}
				initialOpen={false}
			>
				<p>
					{__(
						'Charter keeps disconnected authorization history for up to 90 days so you can understand why access ended.',
						'charter'
					)}
				</p>
				<div className="charter-history-list">
					{data.history.map((grant) => (
						<div
							className="charter-history-item"
							key={`${grant.id}-${grant.disconnectedAt}`}
						>
							<div>
								<h3>{grant.application}</h3>
								<p>{grant.reason}</p>
							</div>
							<time>{grant.disconnectedAt}</time>
							<TechnicalDetails>
								<p>
									<strong>
										{__('Client ID', 'charter')}
									</strong>
									<code>{grant.clientId}</code>
								</p>
								<p>
									<strong>{__('Scopes', 'charter')}</strong>
									<code>{grant.scopes.join(' ')}</code>
								</p>
							</TechnicalDetails>
						</div>
					))}
				</div>
			</PanelBody>
		</section>
	);
}

function monogram(value) {
	const words = String(value || '')
		.replace(/[^a-z0-9 ]/gi, ' ')
		.trim()
		.split(/\s+/)
		.filter(Boolean);
	return (
		words
			.slice(0, 2)
			.map((word) => word[0])
			.join('') || 'A'
	).toUpperCase();
}

const root = document.getElementById('charter-connected-apps-root');
if (root) {
	createRoot(root).render(<ConnectedApps />);
}
