# SwiftSlot

FastAPI SaaS for clinic waitlist recovery, appointment workflows, broadcasts, and clinic readiness checks.

## Deployment Checklist

Set these environment variables in Render:

- `DATABASE_URL`
- `RENDER_EXTERNAL_URL`
- `RESEND_API_KEY`
- `RESEND_FROM_EMAIL`
- `TOKEN_SECRET`
- `SESSION_SECRET`
- `SESSION_COOKIE_SECURE=true`
- `FOUNDER_ADMIN_EMAILS=your@email.com` for founder admin access. Use comma-separated emails for multiple admins.
- `ALLOW_DEMO_SEED=false`
- `ALLOW_DEBUG_ENDPOINTS=false`

Before emailing real patients:

- Verify the Resend sending domain.
- Replace the `resend.dev` test sender with a verified domain sender.
- Use `swiftslot.onrender.com` as a fallback test URL.

Custom domain DNS should point to Render:

- `A` record for `@` -> `216.24.57.1`
- `CNAME` record for `www` -> `swiftslot.onrender.com`

Do not commit real credentials or production secrets.

## Pilot Launch Admin

Founder admin access is granted when a logged-in user's role is `founder_admin`, or when their login email matches `FOUNDER_ADMIN_EMAILS` case-insensitively.

Temporarily enable demo seed tools only while testing:

- `ALLOW_DEMO_SEED=true`

Disable demo and debug endpoints in production:

- `ALLOW_DEBUG_ENDPOINTS=false`
- `ALLOW_DEMO_SEED=false`
