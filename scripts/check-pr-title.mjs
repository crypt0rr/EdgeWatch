import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const pullRequestTitlePattern = /^(?:feat|fix|perf|test|docs|chore|refactor|ci|build)(?:\([^)]+\))?: [^\r\n]+$/

export function isAllowedPullRequestTitle(title) {
  return typeof title === 'string'
    && !/[\r\n]/.test(title)
    && pullRequestTitlePattern.test(title)
}

const invokedDirectly = process.argv[1]
  && import.meta.url === pathToFileURL(resolve(process.argv[1])).href

if (invokedDirectly && !isAllowedPullRequestTitle(process.env.PR_TITLE)) {
  console.error('Pull request title must match <type>(optional-scope): <description>.')
  console.error('Allowed types: feat, fix, perf, test, docs, chore, refactor, ci, build.')
  process.exitCode = 1
}
