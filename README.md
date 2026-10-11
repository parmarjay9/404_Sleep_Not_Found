# WebCompass

WebCompass is a website and Chrome extension that uses age bands to restrict access on selected sites.

## Run locally

1. Install Node.js 20.19 or later.
2. In this folder, copy `.env.example` to `.env`. Add your Supabase project URL and publishable key if they are not already configured. Keep `.env` private; Git ignores it.
3. In Supabase **Authentication** settings, turn off **Confirm email** for immediate signup.
4. In the Supabase SQL Editor, run `schema.sql`.
5. Start WebCompass:

   ```sh
   npm start
   ```

6. Open [http://localhost:3000](http://localhost:3000).

To install the browser extension, open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the `extension/` folder.

## Choose an age option

- **Upload ID:** OCR runs in your browser and suggests a birth date. Review it before submitting. This is not identity verification, and the date cannot unlock age-restricted sites by itself.
- **I don’t have an ID:** Creates a child-limited Under 13 profile. This is self-selected, not verified, and will block sites with higher minimum-age requirements.
- **Verified access:** Requires an approved document-and-selfie check from a configured live Veriff integration. Without that setup, verified access stays disabled.

To enable Veriff, set `VERIFICATION_PROVIDER=veriff` and provide the integration credentials in the backend `.env`. Keep `SUPABASE_SERVICE_KEY` there too; never put it in the website, extension, or GitHub. See [Veriff’s setup guide](https://devdocs.veriff.com/docs/how-to-create-an-integration). Test credentials do not verify real IDs.

## Privacy and limits

Supabase Auth stores account emails and password hashes. Supabase stores profile birth dates and age status. OCR processes the image in the browser; WebCompass stores only the date you approve. If you use Veriff, the provider processes the ID and selfie under its own policies; WebCompass stores the approved date, not the images.

The publishable Supabase key is meant for browser use. Keep profile access protected by the policies in `schema.sql`. Barcode/OCR results and child status are not proof of identity. Site age rules are project settings, not official legal guidance.

## Checks

Run the test suite with:

```sh
npm test
```

Edit `extension/site-ratings.json` to change rated sites, then run `npm run build:rules` and reload the extension in Chrome.