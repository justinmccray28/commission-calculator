# Commission Calculator

## Invite-only pilot

`server.mjs` provides an authenticated version of the existing calculator. It serves both `index.html` and `commission-data.json` only to signed-in agents. The formula code and verified rates remain unchanged. The pilot does not collect payment or store cases. Saved calculator defaults still live on each device.

To run it, use Node 20 or later and set `APP_ORIGIN`, `SUPABASE_URL`, and `SUPABASE_PUBLISHABLE_KEY` as shown in `.env.example`. Environment files are not loaded automatically; set the variables in your hosting provider or run locally with `node --env-file=.env server.mjs` after copying `.env.example` to `.env` and replacing its placeholders. `npm start` works when the variables are already set. No package installation is needed.

The Supabase project is `Commission Calculator Pilot` (`nthbplogfshzkgxwiujt`), and public sign-ups are disabled with email confirmation on. Add the deployed `https://YOUR-DOMAIN/auth/callback` to Auth redirect URLs, then set the Auth site URL to the deployed origin. In the Supabase Auth user dashboard, invite pilot users by email. Invite and password-reset links return to `/auth/callback`, where the user sets their password. Configure SMTP before sending production invitations. No Supabase service-role key is needed and no keys should be committed. Users can reset passwords from `/recover`.

Deploy as a Node web service from GitHub with start command `npm start`, Node 20+, and the three environment variables above. `APP_ORIGIN` must exactly match the deployed HTTPS origin; it is also used to reject cross-site form submissions. The health check is `/health`. The service does not need a build step. After deployment, open `/login`, invite one agent, test the invitation and password reset, and confirm `/app` and `/api/commission-data` redirect or return 401 when signed out.

**Important:** The GitHub Pages deployment below remains a public copy of the whole calculator and JSON. Do not market this as exclusive or protected while that Pages URL or a public source repository still exposes them. Move the source to a private repository and disable the public Pages deployment before using protected access as a subscription gate. Authentication can be piloted independently of that migration.

An early working version of the commission calculator. `index.html` holds the interface and calculation logic; `commission-data.json` holds contract percentages, product payout rates, and monthly trail rates. There is no build step or server-side storage.

## Live calculator

Open https://justinmccray28.github.io/commission-calculator/ in Safari or another browser. You can add that page to your phone's Home Screen. The public GitHub repository is https://github.com/justinmccray28/commission-calculator.

To update rates, edit `commission-data.json` on GitHub, preserving the product keys and valid JSON syntax, and commit to `main`. To change the interface or formulas, edit `index.html` instead. GitHub Pages publishes the new version from the root of that branch. Refresh the webpage to load the update; teammates use the same URL. Publishing changes can take up to 10 minutes. Opening a downloaded HTML file inside ChatGPT may not run its JavaScript, so use the published page.

Term products are grouped in the product dropdown. Their available policy lengths and corresponding payout keys are listed under `termProducts` in `commission-data.json`; the rate for each length remains under `presets`. Non-term product names, carrier assignment, first-year assumptions, and product types are in `catalog`. Choose a carrier, then a term product, then a policy length to load the correct rate.

## Working on the calculator

Serve the folder with a local web server to check the interface; opening `index.html` as a local file may block the JSON request. Keep the rates in `commission-data.json` as percentages (for example, `4.6118` means 4.6118%, and `0.035` means 0.0350% monthly). Review premium basis, option selection, splits, overrides, and trails together before publishing. Do not put client names or case data in the repository or its commit history.

IUL estimates use initial compensation on target premium only. Excess-premium and renewal compensation can exist but are informational and are not calculated in later years.

The September 2026 supplied screenshots added Nationwide Indexed UL Accumulator II (2026), Nationwide Protector II 2020 and Accumulator II 2020, Transamerica Trendsetter LB, Financial Foundation IUL II, Financial Choice IUL II and Lifetime WL, Pacific Life Promise Term, Elite Term 2025, Promise GUL and Horizon IUL 2. Only the shown first-year/initial target rate is calculated. Nationwide rates with rider conditions apply only under the configuration shown in each product's information note. Lifetime WL requires specified coverage to choose its $25,000–$99,999 or $100,000+ band.

North American ADvantage 10/15/20/30 uses monthly term premium multiplied by 12, with first-year rates of 58.6950%, 62.8875%, 79.6575%, and 79.6575% respectively. Pacific Horizon ECV IUL uses the Base/LTC Target 1 initial rate of 96.4275% on target premium. SVER-I3 and later target bands are excluded.

This version stores no submitted cases. Payouts are calculated in the visitor's browser.
