# Manage connected applications

Charter lets applications ask for limited access to protected WordPress REST operations in your name. WordPress permissions still decide which operations your account may perform.

## Review an authorization request

Before approving access, review:

- The application name.
- The protected WordPress site or resource.
- Each requested permission.
- Whether the application asks for continuing access.
- Any warning about local loopback callback addresses.

Approve only applications and callback destinations you recognize. Continuing access lets the application refresh access without asking you to approve every session, subject to Charter's inactivity and absolute limits.

A Client ID Metadata Document application may publish its name, redirects, and grant policy at its HTTPS client ID URL. A material change to that metadata requires new consent.

## Review current access

Open **Profile > Connected Apps**. Each active authorization shows the application, resource, permissions, continuing-access state, authorization time, and last activity.

Charter may reuse an exact active authorization without another prompt. A changed resource, scope, redirect, continuing-access request, client policy, expiry, or revocation requires consent again.

## Disconnect an application

Under **Profile > Connected Apps**, select **Disconnect** for the exact authorization. Charter closes its access tokens, refresh-token family, and pending descendants. The application may ask you to authorize again unless an administrator has blocked or deleted it.

Your password change, account deletion, or removal from a Multisite site also closes affected authorizations. Charter groups recent disconnection reasons into a dashboard notice and retains terminal grant history for 90 days.

If you do not recognize an application, disconnect it and contact the site administrator. A site-wide OAuth lockdown can stop all Charter Bearer access while the administrator investigates.
