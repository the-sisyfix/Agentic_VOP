import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

const APP_NAME = 'sisyfix'

// Browser tab title for each route. Keep in sync with the routes in main.jsx.
const TITLES = {
  '/login': 'Login',
  '/signup': 'Sign Up',
  '/dashboard': 'Dashboard',
  '/chat': 'Chat',
  '/issues': 'Issues',
  '/assets': 'Assets',
  '/remediation': 'Remediation',
  '/validation': 'Validation',
  '/integrations': 'Integrations',
  '/agents': 'Agents',
  '/activity': 'Activity',
  '/reports': 'Reports',
  '/alerts': 'Alerts',
  '/policies': 'Policies',
  '/settings': 'Settings',
  '/admin/dashboard': 'Dashboard',
  '/admin/users': 'User Management',
  '/admin/issues': 'Issues',
  '/admin/remediation': 'Remediation',
  '/admin/documents': 'Document Manager',
  '/admin/analytics': 'Analytics',
  '/admin/agents': 'Agents',
  '/admin/settings': 'System Settings',
}

export default function RouteTitle() {
  const { pathname } = useLocation()

  useEffect(() => {
    const page = TITLES[pathname.replace(/\/+$/, '') || '/']
    document.title = page ? `${APP_NAME}-${page}` : APP_NAME
  }, [pathname])

  return null
}
