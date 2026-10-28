# PC Slow Watch Browser Monitor

## Install locally

1. In Chrome open `chrome://extensions`; in Edge open `edge://extensions`.
2. Enable Developer mode.
3. Choose **Load unpacked** and select this `browser_extension` folder.
4. Reload already-open web tabs so the content script starts on them.

The extension is enabled by default. It stores performance metadata in local extension storage and never transmits it over the network. Samples are stored in separate five-minute buckets instead of rewriting the entire history on every sample; old buckets are pruned after 7 days and at most 20,000 samples are retained. Export through the extension popup, then use **ייבא מדידות דפדפן** in the desktop app.

## Permission note

The extension requests access to HTTP/HTTPS pages so it can collect per-page timing measurements on banking and email sites. Review the source before enabling it. The code does not read titles, visible text, input values, form fields, message subjects, URL paths or query parameters, or screenshots. It records a root-domain label and page-performance metrics only. Gmail thread ID is the only exception to path minimization, and only the opaque ID token is retained (no mailbox index or email content).

Metrics include long-task timing, resource count and transfer-size estimates, DOM node count, page-load timing and JavaScript heap if exposed. They are proxies for per-tab load, not exact per-tab CPU usage. Records are retained for up to 7 days and at most 20,000 samples. Toggle monitoring or clear records in the popup.
