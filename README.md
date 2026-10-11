# WebCompass

Chrome enforces access to a small list of rated websites; the web app handles accounts, verification status, and setup guidance. This folder updates your uploaded project with four age bands and browser navigation rules.

## Start here

1. Install Node **20.19+** (Node 22 or 24 also works).
2. Open a terminal in this folder and run:

   ```bash
   cp .env.example .env
   npm start
   ```

3. Open **http://localhost:3000**. Website and backend now share this one address. Stop your old backend if port 3000 is occupied. You no longer need Vite or a separate server on port 5500. No npm dependencies need downloading.
4. In Chrome, open **chrome://extensions**, turn on **Developer mode**, click **Load unpacked**, and select this project's **extension/** folder. Pin **WebCompass**. Disable the older **AgeGate Demo** extension.
5. Open **https://example.org/**. Without a verified pass, you should see the WebCompass explanation screen. This first check needs no ID provider.

The public Supabase project settings from your upload are preserved. Change them in `.env` if you use another project; the website and extension read the public settings from the backend. Never put the private service-role key in the website or extension.

## Connect automatic age verification

Your existing Supabase project handles accounts and protected birthdates. The homepage's **Upload ID** option runs Tesseract OCR in the browser and saves only a user-reviewed DOB claim to the profile; the ID image is not sent to the backend. OCR is not identity verification, and OCR claims never issue an age pass. The optional Veriff document + selfie integration performs provider verification; only its approved result is marked `verified` and can issue an age pass. This project does not use Stripe.

1. In your **existing Supabase project**, open the SQL Editor and run `schema.sql`. It can be rerun without recreating the table or deleting data. It removes user write privileges on profiles while retaining own-profile reads. The schema supports provider-verified birthdates, unverified OCR dates, and child-limited Under 13 profiles. Supabase Auth stores the password hash; do not create a separate password table.
2. Set `SUPABASE_URL` and the public `SUPABASE_ANON_KEY` to that project's settings. Child-limited and OCR-unverified profile writes use authenticated, user-scoped SQL functions and do not need a service-role key. Set `SUPABASE_SERVICE_KEY` privately in the backend `.env` only if you enable provider-verified DOB writes. Never expose that key in the website, extension, or chat.
3. OCR does not require Veriff. To turn an OCR date into a verified age band, obtain a **live** [Veriff integration](https://devdocs.veriff.com/docs/how-to-create-an-integration) for [document + selfie verification](https://devdocs.veriff.com/docs/document-selfie-idv), configured with the [Full Auto engine](https://help.veriff.com/s/article/Veriff-Decision-Engines-Full-Auto-Hybrid). Confirm that your integration supports the ages and countries you intend to serve, including children, before collecting their documents. Enabling an age band in our code does not establish provider eligibility or consent requirements.
4. For optional provider verification, add the following settings to your backend `.env`, using credentials from the live integration. Use the API base URL shown in your provider's portal; it must be an HTTPS Veriff origin.

   ```dotenv
   VERIFICATION_PROVIDER=veriff
   VERIFF_API_KEY=your_live_integration_api_key
   VERIFF_SHARED_SECRET=your_live_integration_shared_secret
   VERIFF_BASE_URL=https://stationapi.veriff.com
   VERIFF_MODE=live
   VERIFF_PRODUCT=document_selfie
   VERIFF_ENGINE=full_auto
   ```

5. In Supabase Auth settings, turn off email confirmation if you want signup to continue without a confirmation email. The homepage uses Supabase Auth's regular signup flow; Supabase stores the email and a password hash. Account creation does not require the backend service key. If confirmation remains enabled, Supabase creates the account but withholds a session, and the homepage explains the setting to change. Apply `schema.sql`, restart `npm start`, and visit `/health` to check `profiles_available` and `verification_available`. Choose **Upload ID** to OCR a photo in the browser, review the suggested date, and save it as unverified, or **I don't have an ID** for a self-selected child-limited Under 13 profile. These profile writes use the signed-in user's JWT and the SQL functions created by the schema. OCR dates and child profiles do not issue age passes. A provider-approved ID check is required for a verified pass. Availability flags report configured settings; they do not prove credentials work. A successful real scan must still be tested.

The provider account is separate from Supabase and may require a paid plan or onboarding. A test integration does not check real documents. `VERIFF_MODE=live` is a backend configuration guard, not proof that an API key belongs to a live integration: Veriff's documented decision response does not supply an independently verified live/test marker. Configure actual live credentials and the required product/engine in the provider portal. Do not relabel test credentials as live or manually force an approval. An OCR or user-entered DOB cannot be marked verified or bypass provider approval.

The frontend's return URL never counts as approval. The authenticated backend fetches `GET /v1/sessions/{id}/decision`, validates the response HMAC, checks both the session ID and its random account-bound reference, and requires an approved decision with a supported identity document and a valid full DOB. The provider's configured document + selfie integration must perform document authenticity, liveness, and selfie-to-ID matching. Our backend does not independently repeat those checks or infer that they ran from the approval code alone.

The local flow polls for results and does **not** require a public webhook or tunnel. For a deployed server, you can also configure the decision webhook as `https://your-domain/veriff/webhook`; it authenticates the notification and re-fetches the decision instead of trusting the posted birthdate. Pending sessions survive server restarts. Repeated start clicks reuse the existing session; a failed user is limited to three newly created sessions per UTC day.

Existing, genuinely verified profiles can also activate passes. Clear any old test-mode or self-entered verification rows before treating them as verified.

Missing or incomplete live verification settings keep age-pass issuance blocked; OCR dates can be stored as unverified claims but cannot unlock rated sites. `VERIFICATION_PROVIDER=none` disables provider verification while retaining activation for previously verified accounts.

Implemented: browser-local ID OCR for unverified DOB claims; automatic provider verifier integration; Supabase sign-up/sign-in; protected-profile age-band calculation; signed one-hour credentials; non-extractable browser device keys; real website redirects; age-band enforcement; friendly block screens; fresh device proofs; nonce replay protection; issuer signature validation; revocation checks; and a site-rating guide. Live provider enrollment and Chrome execution still require testing in your environment; no live ID has been processed by the code-generation session.

## Verify once, then activate your browser

For a local presentation with sample IDs, set `DEMO_VERIFICATION=true` in `.env` and restart. The OCR save screen displays **Verified (Demo)** with the OCR-derived age band, but this is a simulation only: it does not authenticate the document, mark the Supabase profile verified, or issue an age pass. The demo flag is ignored when `NODE_ENV=production`. Never describe or use this demo state as real age verification.

OCR-only dates and child-limited profiles cannot activate a pass. On the website, complete provider document/selfie verification and wait for approval before activating a verified pass.

1. On the website, sign in, complete the automatic document/selfie flow, and wait for approval.
2. Open the extension and sign in to the same account.
3. Choose **Activate my pass**.
4. Open the example links on the website. The pass contains a band, expiry, random credential ID, format version, and public device key. It contains no DOB or account ID.

When the one-hour pass expires, choose **Activate my pass** again in the extension. The backend uses the existing verified DOB to issue a fresh pass; the ID is not rescanned. The new band is recalculated, including birthday changes. The extension checks the pass on every new rated navigation. Device binding proves the browser possesses its private key, not which human is using it.

| Verified band | example.org: 13+ | example.net: 16+ | example.com: 18+ |
| --- | --- | --- | --- |
| Under 13 | Blocked | Blocked | Blocked |
| 13–15 | Allowed | Blocked | Blocked |
| 16–17 | Allowed | Allowed | Blocked |
| 18+ | Allowed | Allowed | Allowed |

These example domains are harmless public pages. YouTube, Instagram, TikTok, Reddit, X/Twitter, Facebook, Snapchat, Discord, Twitch, and Pinterest have **sample project policies** in `extension/site-ratings.json`. Each entry has a canonical `url`, domain aliases, `minimumAge`, and explanation. These values are editable WebCompass policy choices; they do not claim to be official, universal legal minimum ages. Unknown domains open normally. The local `/restricted` page remains a separate 18+ device-proof check.

## Why visits go through an extension page

Static Chrome navigation rules redirect rated sites even before the service worker starts. The extension checks the signed pass locally and asks the backend to validate a fresh device signature, expiry, and revocation. It sends no visited hostname, URL, or browsing history to the backend. The attempted link remains in the extension page's URL fragment.

For a suitable site, it installs a temporary rule for **one exact URL in one tab**, then opens the URL. The rule is removed on navigation completion/error and has timeout cleanup. There are no permanent age-based allow rules that could silently survive a pass expiring. Expiry is checked before admitting new navigations; it cannot erase content already loaded, and document loading may continue after admission. Single-page-app changes within an already loaded document and embedded frames are outside this navigation-only MVP.

The local issuer's public key is pinned on first activation. If `.local-data/issuer.pem` changes, verify the backend before using the popup's **Reset local issuer connection** button. Restarted browser sessions and worker starts clear pending admissions. Keep the local backend running; a failed check keeps the rated site blocked.

## Change the website list

Edit `extension/site-ratings.json`, then run:

```bash
npm run build:rules
```

This rebuilds both redirects and Chrome host permissions from the JSON. Reload WebCompass in `chrome://extensions` and restart the local server to refresh its displayed list. Every configured minimum must be 13, 16, or 18. Whole-domain policies cannot distinguish a safe post from an adult post on the same site.

## Checks

```bash
npm test
```

Automated tests exercise birthday boundaries, all band outcomes, domain matching, navigation rules, ECDSA/Web Crypto interoperability, enrollment, replay, tampering, expiry, and revocation. They also exercise automatic verification approval/rejection, signature checks, account/session substitution, renewal without a repeated ID check, cleanup failures, and restart persistence. External-service responses are isolated fixtures only in tests; runtime calls the actual services. Passing tests do not establish real provider accuracy. A live end-to-end scan and manual Chrome checks are still necessary:

- Unverified: example.org redirects to the friendly explanation.
- Verified: activate an existing verified account and try the three example domains.
- Reloading a rated page checks the pass again.
- Signing out of the extension clears the pass; rated visits lock again.
- Stopping the backend blocks new rated visits with an explanation.
- The popup's private-key check reports that export is blocked.

## Privacy and practical limits

Supabase retains account ID, verified DOB, and verification timestamp. Supabase Auth manages the password hash. This does **not** implement password-derived encryption of local DOB or face data. The provider capture flow handles ID/selfie images; our server does not download, log, or store those images, document numbers, names, or face templates. It retains a private session/account mapping and random reference under `.local-data/verification-sessions.json`; the mapping contains no DOB or image. Raw provider decisions are not saved.

After approval or rejection, the backend requests provider session deletion. Veriff must enable its [deletion endpoint](https://devdocs.veriff.com/apidocs/v1sessionsid-3), which has rate limits and a deletion delay; a request does not mean immediate deletion. A failed deletion remains queued and is retried when the account checks status again, at most once per hour. This prototype has no continuous cleanup worker for inactive accounts. Confirm the provider's retention settings, including incomplete sessions, before enrolling real children. We do not claim that the provider never stores images.

A device signature proves possession of a browser key, not the identity of the person currently using it. Borrowing a parent's verified account can still defeat the intended age assignment. Signing out of the website does not sign out of the extension; clear its pass when sharing a browser. Another browser, another device, disabling/uninstalling the extension, or an unmanaged incognito profile can bypass enforcement. A child can also inspect or alter an unpacked extension. For a stronger boundary, target sites would need to enforce the credential server-side, or the browser would need parent-managed policies.

The Tailwind browser CDN and Supabase browser library need an internet connection. Tailwind's browser build is appropriate for this local hackathon preview; compile the stylesheet before deployment. The server binds to `127.0.0.1` and serves only the public page files. `.env` and `.local-data/issuer.pem` must remain private.

References: [Veriff session creation](https://devdocs.veriff.com/apidocs/v1sessions), [decision API](https://devdocs.veriff.com/apidocs/v1sessionsiddecision-1), [HMAC authentication](https://devdocs.veriff.com/docs/hmac-authentication-and-endpoint-security), [Chrome navigation rules](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest), [extension alarms](https://developer.chrome.com/docs/extensions/reference/api/alarms).
