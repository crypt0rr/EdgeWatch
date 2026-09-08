# Third-party license notices

EdgeWatch bundles the following scanner binary in its container image:

* **Naabu v2.6.1** — Copyright ProjectDiscovery contributors, licensed under
  the MIT License. Source: <https://github.com/projectdiscovery/naabu/tree/v2.6.1>.

The image also installs the distribution-provided **Nmap** and
**nmap-scripts** packages. Their copyright and license notices are retained by
the Alpine packages in the final image. EdgeWatch invokes both binaries
directly with fixed executables; their updaters and configuration-file loading
are disabled by the application.
