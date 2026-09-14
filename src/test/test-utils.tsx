import { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, type MemoryRouterProps } from 'react-router-dom'
import { render, type RenderOptions } from '@testing-library/react'

export function createTestClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
}
export function renderWithProviders(ui: ReactNode, options: RenderOptions & { route?: MemoryRouterProps['initialEntries']; client?: QueryClient } = {}) {
  const { route = ['/'], client = createTestClient(), ...renderOptions } = options
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}><MemoryRouter initialEntries={route}>{children}</MemoryRouter></QueryClientProvider>
  }
  return { client, ...render(ui, { wrapper: Wrapper, ...renderOptions }) }
}
