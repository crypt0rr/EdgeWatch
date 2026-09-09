# Third-party license notices

EdgeWatch bundles the following scanner binary in its container image:

* **Naabu v2.6.1** — Copyright ProjectDiscovery contributors, licensed under
  the MIT License. Source: <https://github.com/projectdiscovery/naabu/tree/v2.6.1>.
  The image is built from immutable commit
  `5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8`, and the Docker build verifies
  that the release tag resolves to this commit.

The image also installs the distribution-provided **Nmap** and
**nmap-scripts** packages. Their copyright and license notices are retained by
the Alpine packages in the final image. EdgeWatch invokes both binaries
directly with fixed executables; their updaters and configuration-file loading
are disabled by the application.
