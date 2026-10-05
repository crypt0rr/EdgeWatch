import { Component, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

type PageErrorBoundaryProps = {
  children: ReactNode
  homePath: string
  homeLabel: string
}

type PageErrorBoundaryState = {
  failed: boolean
}

/** Keeps a route's rendering failure inside the page area, leaving navigation usable. */
export class PageErrorBoundary extends Component<PageErrorBoundaryProps, PageErrorBoundaryState> {
  state: PageErrorBoundaryState = { failed: false }

  static getDerivedStateFromError(): PageErrorBoundaryState {
    return { failed: true }
  }

  render() {
    if (this.state.failed) {
      return <section className="page-error-panel" role="alert" aria-labelledby="page-error-title">
        <div>
          <p className="eyebrow">Page unavailable</p>
          <h1 id="page-error-title">This page could not be displayed.</h1>
          <p className="muted">The page ran into a problem. You can reload it or continue using the rest of EdgeWatch.</p>
        </div>
        <div className="page-error-actions">
          <button className="button secondary" type="button" onClick={() => window.location.reload()}>Reload page</button>
          <Link className="button primary" to={this.props.homePath}>Go to {this.props.homeLabel}</Link>
        </div>
      </section>
    }

    return this.props.children
  }
}
