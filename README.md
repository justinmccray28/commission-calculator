# Commission Calculator

An early working version of the commission calculator. `index.html` holds the interface and calculation logic; `commission-data.json` holds contract percentages, product payout rates, and monthly trail rates. There is no build step or server-side storage.

## Live calculator

Open https://justinmccray28.github.io/commission-calculator/ in Safari or another browser. You can add that page to your phone's Home Screen. The public GitHub repository is https://github.com/justinmccray28/commission-calculator.

To update rates, edit `commission-data.json` on GitHub, preserving the product keys and valid JSON syntax, and commit to `main`. To change the interface or formulas, edit `index.html` instead. GitHub Pages publishes the new version from the root of that branch. Refresh the webpage to load the update; teammates use the same URL. Publishing changes can take up to 10 minutes. Opening a downloaded HTML file inside ChatGPT may not run its JavaScript, so use the published page.

## Working on the calculator

Serve the folder with a local web server to check the interface; opening `index.html` as a local file may block the JSON request. Keep the rates in `commission-data.json` as percentages (for example, `4.6118` means 4.6118%, and `0.035` means 0.0350% monthly). Review premium basis, option selection, splits, overrides, and trails together before publishing. Do not put client names or case data in the repository or its commit history.

This version stores no submitted cases. Payouts are calculated in the visitor's browser.
