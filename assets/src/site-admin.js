import {
	Button,
	Card,
	CardBody,
	CardHeader,
	CheckboxControl,
	ExternalLink,
	Modal,
	Notice,
	RadioControl,
	SearchControl,
	SelectControl,
	TabPanel,
	TextControl,
	ToggleControl,
} from '@wordpress/components';
import { useCopyToClipboard } from '@wordpress/compose';
import { createRoot, useMemo, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import {
	ConfirmAction,
	EmptyState,
	PageHeader,
	Pagination,
	PostForm,
	StatusBadge,
	TechnicalDetails,
	humanizeToken,
	readData,
} from './admin-utils';

const data = readData('charter-site-admin-data');

function SiteAdminApp() {
	const initialTab =
		new URLSearchParams(window.location.search).get('section') ||
		'overview';
	const status = data.enabled
		? 'healthy'
		: data.state === 'prepared'
			? 'attention'
			: 'neutral';

	return (
		<div className="charter-admin-app">
			<PageHeader
				eyebrow={__('OAuth control center', 'charter')}
				title={__('Charter OAuth', 'charter')}
				description={__(
					'Control delegated access to this WordPress site without changing its normal permission system.',
					'charter'
				)}
				status={
					<StatusBadge status={status}>
						{stateLabel(data.state)}
					</StatusBadge>
				}
			/>

			{(data.notices || []).map((notice, index) => (
				<Notice
					key={index}
					status={notice.status}
					isDismissible={false}
				>
					{notice.message}
				</Notice>
			))}
			<AttentionNotice />
			<TrustPath />

			<TabPanel
				className="charter-tabs"
				initialTabName={
					[
						'overview',
						'applications',
						'authorizations',
						'security',
					].includes(initialTab)
						? initialTab
						: 'overview'
				}
				tabs={[
					{ name: 'overview', title: __('Overview', 'charter') },
					{
						name: 'applications',
						title: __('Applications', 'charter'),
					},
					{
						name: 'authorizations',
						title: __('Authorizations', 'charter'),
					},
					{ name: 'security', title: __('Security', 'charter') },
				]}
				onSelect={setSectionInUrl}
			>
				{(tab) => <Section name={tab.name} />}
			</TabPanel>
		</div>
	);
}

function AttentionNotice() {
	if (data.containment?.mode === 'lockdown') {
		return (
			<Notice status="error" isDismissible={false}>
				{__(
					'Lockdown is active. New authorization and every Charter bearer request are blocked.',
					'charter'
				)}
			</Notice>
		);
	}
	if (data.containment?.mode === 'issuance_paused') {
		return (
			<Notice status="warning" isDismissible={false}>
				{__(
					'New authorization and credential issuance are paused. Existing access tokens remain usable.',
					'charter'
				)}
			</Notice>
		);
	}
	if (
		data.signingKey &&
		!['automatic', 'matching'].includes(data.signingKey.status)
	) {
		return (
			<Notice status="error" isDismissible={false}>
				{__(
					'The signing-key state needs attention before Charter can safely issue or validate credentials.',
					'charter'
				)}
			</Notice>
		);
	}

	return null;
}

function TrustPath() {
	const mode = data.containment?.mode;
	const keyHealthy =
		!data.signingKey ||
		['automatic', 'matching'].includes(data.signingKey.status);
	const steps = [
		{
			label: __('Issuer prepared', 'charter'),
			state: data.issuer ? 'healthy' : 'neutral',
		},
		{
			label: __('Issuance active', 'charter'),
			state:
				data.enabled && mode === 'resumed'
					? 'healthy'
					: data.enabled
						? 'attention'
						: 'neutral',
		},
		{
			label: __('Bearer access active', 'charter'),
			state:
				data.enabled && mode !== 'lockdown'
					? 'healthy'
					: data.enabled
						? 'critical'
						: 'neutral',
		},
		{
			label: __('Signing key healthy', 'charter'),
			state: keyHealthy ? 'healthy' : 'critical',
		},
	];

	return (
		<div
			className="charter-trust-path"
			aria-label={__('OAuth operating path', 'charter')}
		>
			{steps.map((step) => (
				<div
					key={step.label}
					className={`charter-trust-step charter-trust-step--${step.state}`}
				>
					<span className="charter-trust-dot" aria-hidden="true" />
					<span>{step.label}</span>
				</div>
			))}
		</div>
	);
}

function Section({ name }) {
	switch (name) {
		case 'applications':
			return <Applications />;
		case 'authorizations':
			return <Authorizations />;
		case 'security':
			return <Security />;
		default:
			return <Overview />;
	}
}

function Overview() {
	const copyIssuerRef = useCopyToClipboard(data.issuer || '');

	return (
		<div className="charter-section-grid">
			<Card className="charter-card charter-card--wide">
				<CardHeader>
					<SectionTitle
						title={__('Issuer and discovery', 'charter')}
					/>
				</CardHeader>
				<CardBody>
					{!data.issuer ? (
						<Notice status="error" isDismissible={false}>
							{__(
								'This site needs a supported canonical bare-origin URL before OAuth can be prepared.',
								'charter'
							)}
						</Notice>
					) : (
						<>
							<div className="charter-copy-row">
								<code>{data.issuer}</code>
								<Button ref={copyIssuerRef} variant="secondary">
									{__('Copy issuer', 'charter')}
								</Button>
							</div>
							<p className="charter-muted">
								{__(
									'Charter uses this exact origin as both the authorization issuer and the default protected resource.',
									'charter'
								)}
							</p>
							<div className="charter-link-list">
								<ExternalLink
									href={data.urls.authorizationServer}
								>
									{__(
										'Authorization server metadata',
										'charter'
									)}
								</ExternalLink>
								<ExternalLink
									href={data.urls.protectedResource}
								>
									{__(
										'Protected resource metadata',
										'charter'
									)}
								</ExternalLink>
							</div>
							{data.actions.enable && (
								<div className="charter-setup-action">
									<h3>{__('Finish setup', 'charter')}</h3>
									<p>
										{__(
											'Open both metadata URLs from the client environment that will use Charter, then confirm they return the expected JSON.',
											'charter'
										)}
									</p>
									<ConfirmAction
										action={data.actions.enable}
										label={__('Enable OAuth', 'charter')}
										title={__(
											'Enable this OAuth issuer?',
											'charter'
										)}
										description={__(
											'This enables registration, authorization, token exchange, refresh, revocation, and bearer access for this exact issuer.',
											'charter'
										)}
										variant="primary"
										extraFields={{
											discovery_verified: '1',
										}}
									/>
								</div>
							)}
						</>
					)}
				</CardBody>
			</Card>

			<RegistrationPolicy />

			<Card className="charter-card charter-card--wide">
				<CardHeader>
					<SectionTitle
						title={__('Recent security activity', 'charter')}
					/>
				</CardHeader>
				<CardBody>
					{data.events.length === 0 ? (
						<EmptyState
							title={__('No security events yet', 'charter')}
							description={__(
								'Lifecycle, authorization, and security changes will appear here.',
								'charter'
							)}
						/>
					) : (
						<ul className="charter-activity-list">
							{data.events.slice(0, 5).map((event, index) => (
								<li key={`${event.time}-${index}`}>
									<span
										className={`charter-event-mark charter-event-mark--${event.outcome === 'success' ? 'healthy' : 'attention'}`}
									/>
									<div>
										<strong>
											{humanizeToken(event.type)}
										</strong>
										<span>
											{humanizeToken(event.reason)}
										</span>
									</div>
									<time>{event.time}</time>
								</li>
							))}
						</ul>
					)}
				</CardBody>
			</Card>
		</div>
	);
}

function RegistrationPolicy() {
	const [enabled, setEnabled] = useState(Boolean(data.dynamicRegistration));
	if (!data.actions.registrationPolicy) {
		return null;
	}

	return (
		<Card className="charter-card">
			<CardHeader>
				<SectionTitle title={__('Registration policy', 'charter')} />
			</CardHeader>
			<CardBody>
				<p>
					{__(
						'Compatible applications can register themselves. Turning this off affects only new registrations.',
						'charter'
					)}
				</p>
				<PostForm
					action={data.actions.registrationPolicy}
					extraFields={enabled ? { dcr_enabled: '1' } : {}}
					className="charter-control-form"
				>
					<ToggleControl
						label={__(
							'Accept new dynamic registrations',
							'charter'
						)}
						checked={enabled}
						onChange={setEnabled}
					/>
					<Button type="submit" variant="primary">
						{__('Save policy', 'charter')}
					</Button>
				</PostForm>
			</CardBody>
		</Card>
	);
}

function Applications() {
	const [query, setQuery] = useState('');
	const [status, setStatus] = useState('current');
	const [registrationOpen, setRegistrationOpen] = useState(false);
	const filtered = useMemo(() => {
		const normalized = query.toLowerCase();
		return data.clients.filter((client) => {
			const matchesStatus =
				status === 'all' ||
				(status === 'current'
					? client.status !== 'deleted'
					: client.status === status);
			return (
				matchesStatus &&
				(client.name.toLowerCase().includes(normalized) ||
					client.id.toLowerCase().includes(normalized))
			);
		});
	}, [query, status]);

	return (
		<section className="charter-tab-section">
			<div className="charter-section-heading">
				<div>
					<h2>{__('Applications', 'charter')}</h2>
					<p>
						{__(
							'Review applications that can request delegated access to this issuer.',
							'charter'
						)}
					</p>
				</div>
				{data.actions.registerClient && (
					<Button
						variant="primary"
						onClick={() => setRegistrationOpen(true)}
					>
						{__('Register application', 'charter')}
					</Button>
				)}
			</div>
			<div className="charter-filters">
				<SearchControl
					label={__('Search applications', 'charter')}
					value={query}
					onChange={setQuery}
				/>
				<SelectControl
					label={__('Status', 'charter')}
					value={status}
					onChange={setStatus}
					__next40pxDefaultSize
					options={[
						{
							label: __('Current applications', 'charter'),
							value: 'current',
						},
						{ label: __('Active', 'charter'), value: 'active' },
						{ label: __('Blocked', 'charter'), value: 'blocked' },
						{ label: __('Deleted', 'charter'), value: 'deleted' },
						{ label: __('All statuses', 'charter'), value: 'all' },
					]}
				/>
			</div>
			{filtered.length === 0 ? (
				<EmptyState
					title={__('No matching applications', 'charter')}
					description={__(
						'Change the search or status filter, or register an application.',
						'charter'
					)}
				/>
			) : (
				<ApplicationList clients={filtered} />
			)}
			{registrationOpen && (
				<RegistrationModal onClose={() => setRegistrationOpen(false)} />
			)}
		</section>
	);
}

function ApplicationList({ clients }) {
	return (
		<div className="charter-table-shell">
			<table className="charter-table charter-table--applications">
				<thead>
					<tr>
						<th>{__('Application', 'charter')}</th>
						<th>{__('Registration', 'charter')}</th>
						<th>{__('Active access', 'charter')}</th>
						<th>{__('Actions', 'charter')}</th>
					</tr>
				</thead>
				<tbody>
					{clients.map((client) => (
						<ApplicationRow key={client.id} client={client} />
					))}
				</tbody>
			</table>
		</div>
	);
}

function ApplicationRow({ client }) {
	const status =
		client.status === 'active'
			? 'healthy'
			: client.status === 'blocked'
				? 'attention'
				: 'neutral';
	return (
		<tr>
			<td data-label={__('Application', 'charter')}>
				<strong>{client.name}</strong>
				<code>{client.id}</code>
			</td>
			<td data-label={__('Registration', 'charter')}>
				<StatusBadge status={status}>
					{humanizeToken(client.status)}
				</StatusBadge>
				<span>{humanizeToken(client.source)}</span>
				<span>{humanizeToken(client.authenticationMethod)}</span>
			</td>
			<td data-label={__('Active access', 'charter')}>
				{client.activeGrants.length === 0 ? (
					<span className="charter-muted">
						{__('No active authorizations', 'charter')}
					</span>
				) : (
					client.activeGrants.map((grant, index) => (
						<span key={index}>
							{grant.user} · <code>{grant.scope}</code>
						</span>
					))
				)}
			</td>
			<td data-label={__('Actions', 'charter')}>
				<div className="charter-row-actions">
					<ConfirmAction
						action={client.actions.block}
						label={__('Block', 'charter')}
						title={__('Block this application?', 'charter')}
						description={__(
							'Blocking revokes its active authorizations and prevents new authorization until a new registration is created.',
							'charter'
						)}
						isDestructive
					/>
					<ConfirmAction
						action={client.actions.delete}
						label={__('Delete', 'charter')}
						title={__('Delete this application?', 'charter')}
						description={__(
							'Deleting permanently closes the registration and revokes its active authorizations. Audit history remains.',
							'charter'
						)}
						isDestructive
					/>
				</div>
			</td>
		</tr>
	);
}

function RegistrationModal({ onClose }) {
	const [clientId, setClientId] = useState('');
	const [clientName, setClientName] = useState('');
	const [redirectUri, setRedirectUri] = useState('');
	const [clientType, setClientType] = useState('public');
	const [refresh, setRefresh] = useState(true);

	return (
		<Modal
			title={__('Register an application', 'charter')}
			onRequestClose={onClose}
			className="charter-registration-modal"
		>
			<p>
				{__(
					'Every application uses Authorization Code with mandatory PKCE S256. Confidential applications receive a secret once.',
					'charter'
				)}
			</p>
			<PostForm
				action={data.actions.registerClient}
				extraFields={{
					client_id: clientId,
					client_name: clientName,
					redirect_uri: redirectUri,
					client_type: clientType,
					...(refresh ? { supports_refresh: '1' } : {}),
				}}
			>
				<div className="charter-form-stack">
					<TextControl
						label={__('Application name', 'charter')}
						value={clientName}
						onChange={setClientName}
						__next40pxDefaultSize
						required
					/>
					<TextControl
						label={__('Client ID', 'charter')}
						value={clientId}
						onChange={setClientId}
						__next40pxDefaultSize
						required
						help={__(
							'Use the identifier the application will send during authorization.',
							'charter'
						)}
					/>
					<TextControl
						label={__('Redirect URI', 'charter')}
						type="url"
						value={redirectUri}
						onChange={setRedirectUri}
						__next40pxDefaultSize
						required
					/>
					<SelectControl
						label={__('Application type', 'charter')}
						value={clientType}
						onChange={setClientType}
						__next40pxDefaultSize
						options={[
							{
								label: __('Public — no secret', 'charter'),
								value: 'public',
							},
							{
								label: __(
									'Confidential — client secret',
									'charter'
								),
								value: 'confidential',
							},
						]}
					/>
					<CheckboxControl
						label={__(
							'Allow rotating refresh tokens after user consent',
							'charter'
						)}
						checked={refresh}
						onChange={setRefresh}
					/>
				</div>
				<div className="charter-modal-actions">
					<Button variant="tertiary" onClick={onClose}>
						{__('Cancel', 'charter')}
					</Button>
					<Button type="submit" variant="primary">
						{__('Register application', 'charter')}
					</Button>
				</div>
			</PostForm>
		</Modal>
	);
}

function Authorizations() {
	const [query, setQuery] = useState('');
	const filtered = data.grants.filter((grant) =>
		`${grant.user} ${grant.application} ${grant.clientId} ${grant.scope}`
			.toLowerCase()
			.includes(query.toLowerCase())
	);
	return (
		<section className="charter-tab-section">
			<div className="charter-section-heading">
				<div>
					<h2>{__('Authorizations', 'charter')}</h2>
					<p>
						{sprintf(
							_n(
								'%d active authorization represents a user on this site.',
								'%d active authorizations represent users on this site.',
								data.grantCount,
								'charter'
							),
							data.grantCount
						)}
					</p>
				</div>
			</div>
			<SearchControl
				className="charter-search"
				label={__('Search authorizations', 'charter')}
				value={query}
				onChange={setQuery}
			/>
			{filtered.length === 0 ? (
				<EmptyState
					title={__('No matching authorizations', 'charter')}
					description={
						data.grantCount
							? __(
									'Change the search to see other authorizations.',
									'charter'
								)
							: __(
									'Applications will appear here after a user grants access.',
									'charter'
								)
					}
				/>
			) : (
				<div className="charter-table-shell">
					<table className="charter-table">
						<thead>
							<tr>
								<th>{__('Application and user', 'charter')}</th>
								<th>{__('Access', 'charter')}</th>
								<th>{__('Activity', 'charter')}</th>
								<th>{__('Action', 'charter')}</th>
							</tr>
						</thead>
						<tbody>
							{filtered.map((grant) => (
								<AuthorizationRow
									key={grant.id}
									grant={grant}
								/>
							))}
						</tbody>
					</table>
				</div>
			)}
			<Pagination
				pagination={data.grantPagination}
				previousLabel={__('Previous authorizations', 'charter')}
				nextLabel={__('Next authorizations', 'charter')}
			/>
		</section>
	);
}

function AuthorizationRow({ grant }) {
	return (
		<tr>
			<td data-label={__('Application and user', 'charter')}>
				<strong>{grant.application}</strong>
				<span>{grant.user}</span>
				<code>{grant.clientId}</code>
			</td>
			<td data-label={__('Access', 'charter')}>
				<code>{grant.scope}</code>
				<StatusBadge
					status={grant.continuingAccess ? 'info' : 'neutral'}
				>
					{grant.continuingAccess
						? __('Continuing access', 'charter')
						: __('Session access', 'charter')}
				</StatusBadge>
				<TechnicalDetails>
					<p>
						<strong>{__('Resource', 'charter')}</strong>
						<code>{grant.resource}</code>
					</p>
				</TechnicalDetails>
			</td>
			<td data-label={__('Activity', 'charter')}>
				<span>
					{__('Authorized', 'charter')}: {grant.authorizedAt}
				</span>
				<span>
					{__('Last activity', 'charter')}: {grant.lastUsedAt}
				</span>
			</td>
			<td data-label={__('Action', 'charter')}>
				<ConfirmAction
					action={grant.action}
					label={__('Revoke', 'charter')}
					title={__('Revoke this authorization?', 'charter')}
					description={__(
						'The application will immediately lose this user’s active and continuing access.',
						'charter'
					)}
					confirmLabel={__('Revoke authorization', 'charter')}
					isDestructive
					extraFields={{}}
				/>
			</td>
		</tr>
	);
}

function Security() {
	return (
		<section className="charter-tab-section">
			<div className="charter-section-heading">
				<div>
					<h2>{__('Security', 'charter')}</h2>
					<p>
						{__(
							'Inspect the controls that determine whether Charter can issue and accept credentials.',
							'charter'
						)}
					</p>
				</div>
			</div>
			<div className="charter-section-grid">
				{data.containment && (
					<OperatingMode mode={data.containment.mode} />
				)}
				{data.signingKey && <SigningKey />}
				<AuditLog />
				{data.grantCount > 0 && <DangerZone />}
			</div>
		</section>
	);
}

function OperatingMode({ mode }) {
	const [selected, setSelected] = useState(mode);
	const descriptions = {
		resumed: __(
			'Registration, authorization, exchange, refresh, and bearer access operate normally.',
			'charter'
		),
		issuance_paused: __(
			'Stop new registrations and credentials while existing access tokens remain usable.',
			'charter'
		),
		lockdown: __(
			'Stop issuance and reject every Charter bearer token immediately.',
			'charter'
		),
	};
	return (
		<Card className="charter-card charter-card--wide">
			<CardHeader>
				<SectionTitle
					title={__('Operating mode', 'charter')}
					badge={
						<StatusBadge
							status={
								mode === 'resumed'
									? 'healthy'
									: mode === 'lockdown'
										? 'critical'
										: 'attention'
							}
						>
							{humanizeToken(mode)}
						</StatusBadge>
					}
				/>
			</CardHeader>
			<CardBody>
				<RadioControl
					selected={selected}
					onChange={setSelected}
					options={[
						{
							label: __('Operate normally', 'charter'),
							value: 'resumed',
						},
						{
							label: __(
								'Pause new authorization and issuance',
								'charter'
							),
							value: 'issuance_paused',
						},
						{
							label: __(
								'Lock down all Charter bearer access',
								'charter'
							),
							value: 'lockdown',
						},
					]}
				/>
				<p className="charter-callout-copy">{descriptions[selected]}</p>
				<ConfirmAction
					action={data.modeActions[selected]}
					label={__('Change operating mode', 'charter')}
					title={__('Change Charter’s operating mode?', 'charter')}
					description={descriptions[selected]}
					confirmLabel={
						selected === 'lockdown'
							? __('Start lockdown', 'charter')
							: __('Apply mode', 'charter')
					}
					variant="primary"
					isDestructive={selected === 'lockdown'}
					disabled={selected === mode}
				/>
				<TechnicalDetails>
					<dl className="charter-key-values">
						<div>
							<dt>{__('Last actor', 'charter')}</dt>
							<dd>
								{data.containment.actor ||
									__('Default', 'charter')}
							</dd>
						</div>
						<div>
							<dt>{__('Audit state', 'charter')}</dt>
							<dd>
								{data.containment.audit_pending
									? __('Pending reconciliation', 'charter')
									: __('Recorded', 'charter')}
							</dd>
						</div>
					</dl>
				</TechnicalDetails>
			</CardBody>
		</Card>
	);
}

function SigningKey() {
	const key = data.signingKey;
	const healthy = ['automatic', 'matching'].includes(key.status);
	return (
		<Card className="charter-card">
			<CardHeader>
				<SectionTitle
					title={__('Credential signing key', 'charter')}
					badge={
						<StatusBadge status={healthy ? 'healthy' : 'critical'}>
							{humanizeToken(key.status)}
						</StatusBadge>
					}
				/>
			</CardHeader>
			<CardBody>
				<dl className="charter-key-values">
					<div>
						<dt>{__('Source', 'charter')}</dt>
						<dd>{humanizeToken(key.source)}</dd>
					</div>
					<div>
						<dt>{__('Generation', 'charter')}</dt>
						<dd>{key.generation}</dd>
					</div>
					<div>
						<dt>{__('Replacements adopted', 'charter')}</dt>
						<dd>{key.adoption_count}</dd>
					</div>
					<div>
						<dt>{__('Audit', 'charter')}</dt>
						<dd>
							{key.audit_pending
								? __('Pending reconciliation', 'charter')
								: __('Recorded', 'charter')}
						</dd>
					</div>
				</dl>
				{key.database_fallback && (
					<Notice status="warning" isDismissible={false}>
						{__(
							'WordPress is supplying part of the key material from database-backed fallback state. OAuth remains available.',
							'charter'
						)}
					</Notice>
				)}
				{data.keyActions.reconcile && (
					<ConfirmAction
						action={data.keyActions.reconcile}
						label={__('Retry key audit', 'charter')}
						title={__('Retry the signing-key audit?', 'charter')}
						description={__(
							'Charter will record the already-applied key transition without changing credentials again.',
							'charter'
						)}
						extraFields={{}}
					/>
				)}
				{data.keyActions.adopt && (
					<ConfirmAction
						action={data.keyActions.adopt}
						label={__('Adopt replacement', 'charter')}
						title={__(
							'Adopt this exact key replacement?',
							'charter'
						)}
						description={__(
							'Earlier Charter credentials will remain unusable. Registrations, grants, and audit history are preserved.',
							'charter'
						)}
						confirmLabel={__('Adopt replacement', 'charter')}
						isDestructive
					/>
				)}
				<TechnicalDetails>
					<p>
						{__(
							'Charter does not back up, export, escrow, recover, overlap, or migrate signing keys or credentials.',
							'charter'
						)}
					</p>
				</TechnicalDetails>
			</CardBody>
		</Card>
	);
}

function AuditLog() {
	return (
		<Card className="charter-card charter-card--wide">
			<CardHeader>
				<SectionTitle title={__('Security history', 'charter')} />
			</CardHeader>
			<CardBody className="charter-card-body--flush">
				{data.events.length === 0 ? (
					<EmptyState title={__('No recorded events', 'charter')} />
				) : (
					<div className="charter-table-shell">
						<table className="charter-table">
							<thead>
								<tr>
									<th>{__('Time', 'charter')}</th>
									<th>{__('Event', 'charter')}</th>
									<th>{__('Application', 'charter')}</th>
									<th>{__('Outcome', 'charter')}</th>
								</tr>
							</thead>
							<tbody>
								{data.events.map((event, index) => (
									<tr key={`${event.time}-${index}`}>
										<td data-label={__('Time', 'charter')}>
											{event.time}
										</td>
										<td data-label={__('Event', 'charter')}>
											<strong>
												{humanizeToken(event.type)}
											</strong>
											<code>{event.reason}</code>
										</td>
										<td
											data-label={__(
												'Application',
												'charter'
											)}
										>
											<code>{event.client || '—'}</code>
										</td>
										<td
											data-label={__(
												'Outcome',
												'charter'
											)}
										>
											<StatusBadge
												status={
													event.outcome === 'success'
														? 'healthy'
														: 'attention'
												}
											>
												{humanizeToken(event.outcome)}
											</StatusBadge>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</CardBody>
		</Card>
	);
}

function DangerZone() {
	return (
		<Card className="charter-card charter-card--wide charter-danger-zone">
			<CardHeader>
				<SectionTitle title={__('Danger zone', 'charter')} />
			</CardHeader>
			<CardBody>
				<h3>{__('Revoke all site access', 'charter')}</h3>
				<p>
					{__(
						'Permanently disconnect every active OAuth authorization for this issuer. Applications remain registered and users may authorize them again.',
						'charter'
					)}
				</p>
				<ConfirmAction
					action={data.actions.revokeAll}
					label={__('Revoke all authorizations', 'charter')}
					title={__('Revoke all site authorizations?', 'charter')}
					description={sprintf(
						_n(
							'This immediately disconnects %d active authorization.',
							'This immediately disconnects %d active authorizations.',
							data.grantCount,
							'charter'
						),
						data.grantCount
					)}
					confirmLabel={__('Revoke all authorizations', 'charter')}
					isDestructive
					extraFields={{ confirm_revocation: '1' }}
				/>
			</CardBody>
		</Card>
	);
}

function SectionTitle({ title, badge }) {
	return (
		<div className="charter-card-title">
			<h2>{title}</h2>
			{badge}
		</div>
	);
}

function stateLabel(state) {
	return state === 'enabled'
		? __('OAuth enabled', 'charter')
		: state === 'prepared'
			? __('Setup required', 'charter')
			: humanizeToken(state);
}

function setSectionInUrl(section) {
	const url = new URL(window.location.href);
	url.searchParams.set('section', section);
	window.history.replaceState({}, '', url);
}

const root = document.getElementById('charter-site-admin-root');
if (root) {
	createRoot(root).render(<SiteAdminApp />);
}
