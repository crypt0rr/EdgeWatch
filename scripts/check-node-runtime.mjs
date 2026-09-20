const [major, minor] = process.versions.node.split('.').map(Number)

if (major !== 24 || minor < 16) {
  console.error(`EdgeWatch frontend tooling requires Node.js >=24.16.0 <25; found ${process.versions.node}.`)
  console.error('Use the version in .node-version or the project runtime documented in README.md.')
  process.exit(1)
}
