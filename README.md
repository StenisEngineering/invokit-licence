# InvoKit Pro Manual Licence Stack

This is a medium-security starter stack for your offline-first app.

## What it includes
- Cloudflare Worker API for manual licence generation and validation
- D1 SQL schema for licences and activations
- Small admin HTML tool for generating, revoking, and finding licences
- One-time online activation model for the app, then offline afterwards

## Security level
This is **medium security**, not perfect anti-piracy.

It is stronger than plain visible keys because it:
- stores only a hash of the licence key in D1
- signs activation payloads with HMAC-SHA256
- enforces activation count per licence
- supports revoke and search
- keeps the admin secret out of the public app

It does **not** fully stop copying by determined attackers because browser apps can still be studied and local storage can still be tampered with by advanced users.

## Cloudflare setup
Cloudflare Workers supports Web Crypto, D1 bindings, and timing-safe secret comparison, which fits this design. citeturn454796search1turn454796search2turn454796search3turn454796search4

### 1) Create a D1 database
Use Wrangler or the Cloudflare dashboard to create a D1 database and bind it to your Worker. Cloudflare documents D1 bindings for Workers and Pages. citeturn454796search2turn454796search4turn454796search11

### 2) Import the schema
Run:

```bash
wrangler d1 execute invokit_licences --file=./schema.sql
```

### 3) Set Worker secrets
Set these secrets:
- `ADMIN_SECRET` = long random secret used only by the admin generator
- `KEY_PEPPER` = random secret used when hashing licence keys
- `ACTIVATION_SECRET` = random secret used to sign activation tokens
- `ALLOWED_ORIGIN` = your admin panel origin, for example `https://admin-invokit.pages.dev`

### 4) Deploy the Worker
Update `wrangler.toml` with your real D1 database ID, then deploy.

### 5) Deploy the admin page
Upload `admin/index.html` to your admin Pages project. In that file, keep:

```js
const API_BASE = 'https://licence.getinvokitpro.com';
```

pointing to your Worker custom domain.

## Worker endpoints
### POST `/generate`
Admin only. Creates and saves a new licence.

### POST `/validate`
Public app endpoint. The app sends:
- `key`
- `installId`
- optional `deviceName`
- optional `appVersion`

If valid, the Worker returns a signed activation token.

### POST `/revoke`
Admin only. Revokes a licence.

### GET `/find?email=...` or `/find?serial=...`
Admin only. Searches licences.

## App integration
Your app should do this on first activation:
1. user enters licence key
2. app generates or loads a stable `installId`
3. app sends `{ key, installId, deviceName, appVersion }` to `/validate`
4. app stores the returned activation token locally
5. later app launches trust the stored activation token and do not need the internet again

## Example app-side activation request
```js
async function validateLicenceOnline(key) {
  const installId = localStorage.getItem('invokit_install_id') || crypto.randomUUID();
  localStorage.setItem('invokit_install_id', installId);

  const res = await fetch('https://licence.getinvokitpro.com/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      key,
      installId,
      deviceName: navigator.userAgent,
      appVersion: '1.0.0'
    })
  });

  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || 'Activation failed');

  localStorage.setItem('invokit_activation', JSON.stringify(data.activation));
  return data.activation;
}
```

## Weekend-launch recommendation
Use this manual stack first:
- buyer pays on Selar
- you generate the licence in the admin tool
- you email the licence key manually
- buyer activates once
- app works offline afterwards

Then add later:
- Lemon Squeezy webhook
- Selar webhook
- automatic email delivery
