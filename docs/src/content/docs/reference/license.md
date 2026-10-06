---
title: License and source code
description: Understand EdgeWatch licensing, bundled notices, and the source link for modified builds.
---

Copyright (c) 2026 Bart. EdgeWatch is released under
[AGPL-3.0-only](https://github.com/crypt0rr/EdgeWatch/blob/docs/website-preview/LICENSE). Bundled components keep their separate licenses;
see [third-party notices](https://github.com/crypt0rr/EdgeWatch/blob/docs/website-preview/THIRD_PARTY_LICENSES.md).
Releases before v0.25.0 retain their previously published MIT terms.

The console's **Source code** link is public, including on sign-in and public
status pages. An official release links to its exact Git tag. If you deploy a
modified or forked build, publish its complete corresponding source and build
instructions, then set `web.source_url` in `config.yaml` to that HTTPS location.
Without an override, a development build links to the upstream repository,
which does not represent local modifications. Changing the source link does
not change the obligations of the license.
