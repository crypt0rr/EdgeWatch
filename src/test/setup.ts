import '@testing-library/jest-dom/vitest'
import { notifyManager } from '@tanstack/react-query'
import { cleanup } from '@testing-library/react'
import { act } from 'react'
import { afterAll, afterEach, beforeAll } from 'vitest'

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const actWarning = /not wrapped in act\(/i
const originalConsoleError = console.error
const originalConsoleWarn = console.warn
let actWarningCount = 0

function failOnActWarning(original: (...args: unknown[]) => void) {
  return (...args: unknown[]) => {
    if (args.some((value) => actWarning.test(String(value)))) {
      actWarningCount += 1
    }
    original(...args)
  }
}

beforeAll(() => {
  console.error = failOnActWarning(originalConsoleError)
  console.warn = failOnActWarning(originalConsoleWarn)
  notifyManager.setNotifyFunction((callback) => {
    act(callback)
  })
})

afterEach(() => cleanup())

afterAll(() => {
  console.error = originalConsoleError
  console.warn = originalConsoleWarn
  if (actWarningCount > 0 && process.env.EDGEWATCH_REPORT_ACT_WARNINGS === '1') {
    throw new Error(`React act warnings observed: ${actWarningCount}`)
  }
})
