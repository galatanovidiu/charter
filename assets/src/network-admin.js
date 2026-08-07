import {
	Card,
	CardBody,
	CardHeader,
	Notice,
	PanelBody,
	RadioControl,
	SearchControl,
} from '@wordpress/components';
import { createRoot, useMemo, useState } from '@wordpress/element';
import { __, _n, sprintf } from '@wordpress/i18n';
import {
	ConfirmAction,
	EmptyState,
	PageHeader,
	Pagination,
	StatusBadge,
	TechnicalDetails,
	humanizeToken,
	readData,
} from './admin-utils';

const data = readData('charter-network-admin-data');

function NetworkAdminApp() {
	return (
		<div className="charter-admin-app charter-network-admin">
			<PageHeader
				eyebrow={__('Network control plane', 'charter')}
				title={__('Charter OAuth', 'charter')}
				description={__(
					'Inspect and govern each site’s isolated OAuth issuer. Charter does not create network clients, grants, credentials, or a network OAuth issuer.',
					'charter'
				)}
				status={
					<StatusBadge status="info">
						{__('Isolated by site', 'charter')}
					</StatusBadge>
				}
			/>
			{data.notice && (
				<Notice status={data.notice.status} isDismissible>
					{data.notice.message}
				</Notice>
			)}
			{data.invalidSite && (
				<Notice status="error" isDismissible={false}>
					{__(
						'The selected site is unavailable, outside this network, or not operable.',
						'charter'
					)}
				</Notice>
			)}

			<SiteBrowser />
			{data.selected && <SelectedSite site={data.selected} />}
			<NetworkActions />
		</div>
	);
}

function SiteBrowser() {
	const [query, setQuery] = useState('');
	const sites = useMemo(
		() =>
			data.sites.filter((site) =>
				`${site.id} ${site.domainPath}`
					.toLowerCase()
					.includes(query.toLowerCase())
			),
		[query]
	);
	return (
		<section
			className="charter-site-browser"
			aria-labelledby="charter-network-sites-title"
		>
			<div className="charter-section-heading">
				<div>
					<h2 id="charter-network-sites-title">
						{__('Network sites', 'charter')}
					</h2>
					<p>
						{__(
							'Choose one site to inspect its exact issuer state and controls.',
							'charter'
						)}
					</p>
				</div>
			</div>
			<SearchControl
				className="charter-search"
				label={__('Search sites', 'charter')}
				value={query}
				onChange={setQuery}
			/>
			{sites.length === 0 ? (
				<EmptyState
					title={__('No matching sites', 'charter')}
					description={__(
						'Change the search or move to another page of sites.',
						'charter'
					)}
				/>
			) : (
				<div className="charter-site-list">
					{sites.map((site) => (
						<a
							key={site.id}
							href={site.url}
							className={`charter-site-row${site.selected ? ' is-selected' : ''}`}
							aria-current={site.selected ? 'page' : undefined}
						>
							<span className="charter-site-id">
								{sprintf(__('Site #%d', 'charter'), site.id)}
							</span>
							<code>{site.domainPath}</code>
							<span>
								{site.selected
									? __('Selected', 'charter')
									: __('Inspect site', 'charter')}
							</span>
						</a>
					))}
				</div>
			)}
			<Pagination
				pagination={data.sitePagination}
				previousLabel={__('Previous sites', 'charter')}
				nextLabel={__('Next sites', 'charter')}
			/>
		</section>
	);
}

function SelectedSite({ site }) {
	const stateStatus =
		site.state === 'enabled'
			? 'healthy'
			: site.state === 'prepared'
				? 'attention'
				: 'neutral';
	return (
		<section
			className="charter-selected-site"
			aria-labelledby="charter-selected-site-title"
		>
			<div className="charter-selected-site-header">
				<div>
					<p className="charter-eyebrow">
						{sprintf(__('Selected site #%d', 'charter'), site.id)}
					</p>
					<h2 id="charter-selected-site-title">
						{site.issuer || __('Issuer not prepared', 'charter')}
					</h2>
				</div>
				<StatusBadge status={stateStatus}>
					{stateLabel(site.state)}
				</StatusBadge>
			</div>
			<div className="charter-site-facts">
				<span>
					{site.storageReady
						? __('Site storage installed', 'charter')
						: __('Site storage not initialized', 'charter')}
				</span>
				<span>
					{sprintf(
						_n(
							'%d active authorization',
							'%d active authorizations',
							site.grantCount,
							'charter'
						),
						site.grantCount
					)}
				</span>
			</div>

			{site.actions.prepare && (
				<Notice status="info" isDismissible={false}>
					<p>
						{__(
							'Preparing installs site-local storage and publishes discovery metadata. It does not enable authorization or token operations.',
							'charter'
						)}
					</p>
					<ConfirmAction
						action={site.actions.prepare}
						label={__('Prepare site issuer', 'charter')}
						title={__('Prepare this site?', 'charter')}
						description={__(
							'Charter will initialize only this site’s isolated OAuth boundary.',
							'charter'
						)}
						variant="primary"
					/>
				</Notice>
			)}
			{site.actions.enable && (
				<Notice status="warning" isDismissible={false}>
					<p>
						{__(
							'Verify the exact discovery URLs from the intended client environment before enabling this issuer.',
							'charter'
						)}
					</p>
					<ConfirmAction
						action={site.actions.enable}
						label={__('Enable site issuer', 'charter')}
						title={__('Enable this exact issuer?', 'charter')}
						description={__(
							'Registration, authorization, token, refresh, revocation, and bearer operations will become available for this site.',
							'charter'
						)}
						variant="primary"
						extraFields={{ discovery_verified: '1' }}
					/>
				</Notice>
			)}

			{site.state === 'enabled' && (
				<div className="charter-section-grid">
					<SiteOperatingMode site={site} />
					<SiteSigningKey site={site} />
				</div>
			)}
			<SiteAuthorizations site={site} />
			<SiteEvents site={site} />
		</section>
	);
}

function SiteOperatingMode({ site }) {
	const current = site.containment.mode;
	const [selected, setSelected] = useState(current);
	const descriptions = {
		resumed: __(
			'Operate registration, authorization, issuance, refresh, and bearer access normally for this issuer.',
			'charter'
		),
		issuance_paused: __(
			'Pause new authorization and issuance while existing access tokens remain usable.',
			'charter'
		),
		lockdown: __(
			'Pause issuance and reject every Charter bearer token for this issuer.',
			'charter'
		),
	};
	return (
		<Card className="charter-card">
			<CardHeader>
				<CardTitle
					title={__('Operating mode', 'charter')}
					badge={
						<StatusBadge
							status={
								current === 'resumed'
									? 'healthy'
									: current === 'lockdown'
										? 'critical'
										: 'attention'
							}
						>
							{humanizeToken(current)}
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
							label: __('Lock down bearer access', 'charter'),
							value: 'lockdown',
						},
					]}
				/>
				<p className="charter-callout-copy">{descriptions[selected]}</p>
				<ConfirmAction
					action={site.modeActions[selected]}
					label={__('Change mode', 'charter')}
					title={__(
						'Change this issuer’s operating mode?',
						'charter'
					)}
					description={descriptions[selected]}
					confirmLabel={
						selected === 'lockdown'
							? __('Start lockdown', 'charter')
							: __('Apply mode', 'charter')
					}
					variant="primary"
					isDestructive={selected === 'lockdown'}
					disabled={selected === current}
				/>
				<TechnicalDetails>
					<p>
						{__(
							'Containment is reversible and never deletes clients, grants, or credentials.',
							'charter'
						)}
					</p>
				</TechnicalDetails>
			</CardBody>
		</Card>
	);
}

function SiteSigningKey({ site }) {
	const key = site.signingKey;
	const healthy = ['automatic', 'matching'].includes(key.status);
	return (
		<Card className="charter-card">
			<CardHeader>
				<CardTitle
					title={__('Signing key', 'charter')}
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
						<dd>{key.adoptionCount}</dd>
					</div>
					<div>
						<dt>{__('Audit', 'charter')}</dt>
						<dd>
							{key.auditPending
								? __('Pending reconciliation', 'charter')
								: __('Recorded', 'charter')}
						</dd>
					</div>
				</dl>
				{key.databaseFallback && (
					<Notice status="warning" isDismissible={false}>
						{__(
							'This issuer uses database-backed WordPress fallback secret material and remains operational.',
							'charter'
						)}
					</Notice>
				)}
				{site.keyActions.reconcile && (
					<ConfirmAction
						action={site.keyActions.reconcile}
						label={__('Retry key audit', 'charter')}
						title={__('Retry this issuer’s key audit?', 'charter')}
						description={__(
							'Record the already-applied transition without changing credentials again.',
							'charter'
						)}
						extraFields={{}}
					/>
				)}
				{site.keyActions.adopt && (
					<ConfirmAction
						action={site.keyActions.adopt}
						label={__('Adopt replacement', 'charter')}
						title={__('Adopt this exact replacement?', 'charter')}
						description={__(
							'Earlier credentials stay unusable while registrations, grants, and audit history are preserved.',
							'charter'
						)}
						isDestructive
					/>
				)}
			</CardBody>
		</Card>
	);
}

function SiteAuthorizations({ site }) {
	return (
		<Card className="charter-card charter-card--wide charter-site-detail-card">
			<CardHeader>
				<CardTitle title={__('Active authorizations', 'charter')} />
			</CardHeader>
			<CardBody className="charter-card-body--flush">
				{site.grants.length === 0 ? (
					<EmptyState
						title={__('No active authorizations', 'charter')}
						description={__(
							'User grants for this exact issuer will appear here.',
							'charter'
						)}
					/>
				) : (
					<div className="charter-table-shell">
						<table className="charter-table">
							<thead>
								<tr>
									<th>{__('User and client', 'charter')}</th>
									<th>{__('Access', 'charter')}</th>
									<th>{__('Action', 'charter')}</th>
								</tr>
							</thead>
							<tbody>
								{site.grants.map((grant) => (
									<tr key={grant.id}>
										<td
											data-label={__(
												'User and client',
												'charter'
											)}
										>
											<strong>{grant.user}</strong>
											<code>{grant.clientId}</code>
										</td>
										<td
											data-label={__('Access', 'charter')}
										>
											<code>{grant.scope}</code>
											<StatusBadge
												status={
													grant.continuingAccess
														? 'info'
														: 'neutral'
												}
											>
												{grant.continuingAccess
													? __(
															'Continuing access',
															'charter'
														)
													: __(
															'Session access',
															'charter'
														)}
											</StatusBadge>
											<TechnicalDetails>
												<p>
													<strong>
														{__(
															'Resource',
															'charter'
														)}
													</strong>
													<code>
														{grant.resource}
													</code>
												</p>
											</TechnicalDetails>
										</td>
										<td
											data-label={__('Action', 'charter')}
										>
											<ConfirmAction
												action={grant.action}
												label={__('Revoke', 'charter')}
												title={__(
													'Revoke this site authorization?',
													'charter'
												)}
												description={__(
													'The selected user and client immediately lose this authorization.',
													'charter'
												)}
												confirmLabel={__(
													'Revoke authorization',
													'charter'
												)}
												isDestructive
											/>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
				<Pagination
					pagination={site.grantPagination}
					previousLabel={__('Previous authorizations', 'charter')}
					nextLabel={__('Next authorizations', 'charter')}
				/>
				{site.actions.revokeAll && (
					<div className="charter-inline-danger">
						<div>
							<h3>{__('Revoke all site access', 'charter')}</h3>
							<p>
								{__(
									'Permanently disconnect every active authorization for this site issuer.',
									'charter'
								)}
							</p>
						</div>
						<ConfirmAction
							action={site.actions.revokeAll}
							label={__('Revoke all', 'charter')}
							title={__(
								'Revoke all authorizations for this site?',
								'charter'
							)}
							description={sprintf(
								_n(
									'This immediately disconnects %d active authorization.',
									'This immediately disconnects %d active authorizations.',
									site.grantCount,
									'charter'
								),
								site.grantCount
							)}
							confirmLabel={__(
								'Revoke all authorizations',
								'charter'
							)}
							isDestructive
						/>
					</div>
				)}
			</CardBody>
		</Card>
	);
}

function SiteEvents({ site }) {
	return (
		<Card className="charter-card charter-card--wide charter-site-detail-card">
			<CardHeader>
				<CardTitle title={__('Recent security events', 'charter')} />
			</CardHeader>
			<CardBody className="charter-card-body--flush">
				{site.events.length === 0 ? (
					<EmptyState title={__('No recorded events', 'charter')} />
				) : (
					<div className="charter-table-shell">
						<table className="charter-table">
							<thead>
								<tr>
									<th>{__('Time', 'charter')}</th>
									<th>{__('Event', 'charter')}</th>
									<th>{__('Context', 'charter')}</th>
									<th>{__('Outcome', 'charter')}</th>
								</tr>
							</thead>
							<tbody>
								{site.events.map((event, index) => (
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
												'Context',
												'charter'
											)}
										>
											<code>{event.client || '—'}</code>
											<span>
												{event.user
													? sprintf(
															__(
																'User #%d',
																'charter'
															),
															event.user
														)
													: '—'}
											</span>
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

function NetworkActions() {
	const [mode, setMode] = useState('resumed');
	const descriptions = {
		resumed: __(
			'Resume every enabled site issuer in this network.',
			'charter'
		),
		issuance_paused: __(
			'Pause new authorization and issuance independently on every enabled site issuer.',
			'charter'
		),
		lockdown: __(
			'Pause issuance and reject Charter bearer access independently on every enabled site issuer.',
			'charter'
		),
	};
	return (
		<section className="charter-network-actions">
			<PanelBody
				title={__('Network-wide actions', 'charter')}
				initialOpen={false}
			>
				<Notice status="warning" isDismissible={false}>
					{__(
						'These operations visit each live site sequentially and preserve every isolated issuer boundary.',
						'charter'
					)}
				</Notice>
				<div className="charter-section-grid">
					<Card className="charter-card">
						<CardHeader>
							<CardTitle
								title={__('Emergency containment', 'charter')}
							/>
						</CardHeader>
						<CardBody>
							<RadioControl
								selected={mode}
								onChange={setMode}
								options={[
									{
										label: __(
											'Resume all enabled issuers',
											'charter'
										),
										value: 'resumed',
									},
									{
										label: __(
											'Pause issuance on all enabled issuers',
											'charter'
										),
										value: 'issuance_paused',
									},
									{
										label: __(
											'Lock down all enabled issuers',
											'charter'
										),
										value: 'lockdown',
									},
								]}
							/>
							<p>{descriptions[mode]}</p>
							<ConfirmAction
								action={data.networkActions.modes[mode]}
								label={__('Apply across network', 'charter')}
								title={__(
									'Apply this mode to all enabled issuers?',
									'charter'
								)}
								description={descriptions[mode]}
								confirmLabel={
									mode === 'lockdown'
										? __(
												'Lock down enabled issuers',
												'charter'
											)
										: __('Apply network mode', 'charter')
								}
								isDestructive={mode === 'lockdown'}
							/>
						</CardBody>
					</Card>
					<Card className="charter-card">
						<CardHeader>
							<CardTitle
								title={__('Signing-key lifecycle', 'charter')}
							/>
						</CardHeader>
						<CardBody>
							{data.networkActions.signingKeyCount === 0 ? (
								<p>
									{__(
										'No enabled site issuer requires explicit-key adoption or audit reconciliation.',
										'charter'
									)}
								</p>
							) : (
								<>
									<p>
										{sprintf(
											_n(
												'%d isolated issuer needs an exact signing-key action.',
												'%d isolated issuers need exact signing-key actions.',
												data.networkActions
													.signingKeyCount,
												'charter'
											),
											data.networkActions.signingKeyCount
										)}
									</p>
									<ConfirmAction
										action={
											data.networkActions.signingKeyAction
										}
										label={__(
											'Apply exact key batch',
											'charter'
										)}
										title={__(
											'Apply the current network key batch?',
											'charter'
										)}
										description={__(
											'Charter will process each exact issuer transition sequentially and restore the original site after every operation.',
											'charter'
										)}
										confirmLabel={__(
											'Apply key batch',
											'charter'
										)}
										isDestructive
									/>
								</>
							)}
						</CardBody>
					</Card>
				</div>
			</PanelBody>
		</section>
	);
}

function CardTitle({ title, badge }) {
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
			? __('Verification required', 'charter')
			: humanizeToken(state);
}

const root = document.getElementById('charter-network-admin-root');
if (root) {
	createRoot(root).render(<NetworkAdminApp />);
}
