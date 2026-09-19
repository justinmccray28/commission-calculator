# Commission Calculator

An early working version of the commission calculator. It is a self-contained webpage: `index.html` holds the interface, payout rules, and live calculations. There is no build step or server-side storage.

## Publish with GitHub Pages

1. Create a dedicated GitHub repository for this project. On GitHub Free, the repository must be public to use GitHub Pages.
2. Add the files in this folder to the repository's `main` branch. Keep `index.html` at the repository root.
3. In **Settings → Pages**, choose **Deploy from a branch**, then `main` and `/(root)`. Save.
4. Open the URL shown under **Settings → Pages** in Safari or another browser. You can add that page to your phone's Home Screen.

To release a change, edit `index.html` and commit it to `main`. GitHub Pages publishes the new version from that branch. Refresh the webpage to load the update; teammates use the same URL. GitHub says publishing changes can take up to 10 minutes. Opening a downloaded HTML file inside ChatGPT may not run its JavaScript, so use the published page.

## Working on the calculator

Open `index.html` in a desktop browser to check the interface. When editing product payout rules, update the `presets` and `trailRates` objects near the bottom of that file. Review premium basis, option selection, splits, overrides, and trails together before publishing. Do not put client names or case data in the repository or its commit history.

This version stores no submitted cases. Payouts are calculated in the visitor's browser.
