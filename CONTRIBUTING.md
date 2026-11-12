# Contributing

Thanks for helping. Bug reports, board reports ("works on my XYZ board"), docs fixes and code
are all welcome.

## Before you open an issue

- **Bug:** include the board model, the release version (or commit), what you did, what you
  expected, and the serial log if you can get one (`espflash monitor`). Remove passwords,
  Wi-Fi names and public IP addresses from logs first.
- **Security problem:** do not open a public issue; see [SECURITY.md](SECURITY.md).
- **Feature idea:** say what problem it solves. Flash (about 90% used) and RAM are tight, so
  every feature has to earn its bytes.

## Code

- Logic belongs in `dnscore/` with tests; `firmware/` stays a thin layer over ESP-IDF.
  `cd dnscore && cargo test` must pass.
- Match the surrounding style (lines up to about 110 columns; the code is not run through
  `cargo fmt`, so please do not reformat files you did not otherwise change).
- Anything that changes memory use (caches, buffers, tasks, connections) needs a measurement
  on a real board: free heap and its minimum (shown in the web UI) under load. Say in the PR
  what you measured and how.
- Say which parts of a change you ran on hardware and which you did not.
- Web UI: edit only the single `<script>` and `<style>` in `firmware/ui/index.html`. Inline
  `style=` attributes and inline event handlers are blocked by the page's Content Security
  Policy.
- Keep commits free of credentials, personal network details and third-party list data.

See [docs/building.md](docs/building.md) for the toolchain and flashing, and
[docs/design.md](docs/design.md) for how the pieces fit.

By contributing you agree that your contribution is licensed under the MIT licence.
