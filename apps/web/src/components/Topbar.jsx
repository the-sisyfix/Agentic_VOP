import { useState, useRef, useEffect } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { useNavigate } from 'react-router-dom'

import '../styles/Topbar.css'

export default function Topbar() {
  const { signOut, userRole, user } = useAuth()
  const navigate = useNavigate()

  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterOpen, setFilterOpen] = useState(false)
  const [filters, setFilters] = useState({
    critical: true,
    high: true,
    medium: true,
    low: true
  })

  const searchInputRef = useRef(null)
  const filterRef = useRef(null)

  // Focus search input when opened
  useEffect(() => {
    if (searchOpen && searchInputRef.current) {
      searchInputRef.current.focus()
    }
  }, [searchOpen])

  // Close filter dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (filterRef.current && !filterRef.current.contains(event.target)) {
        setFilterOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const handleLogoClick = () => {
    if (userRole === 'admin') {
      navigate('/admin/dashboard')
    } else {
      navigate('/dashboard')
    }
  }

  const handleSearchSubmit = (e) => {
    e.preventDefault()
    if (searchQuery.trim()) {
      navigate(`/issues?search=${encodeURIComponent(searchQuery)}`)
      setSearchOpen(false)
      setSearchQuery('')
    }
  }

  const handleFilterChange = (key) => {
    setFilters(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const handleApplyFilters = () => {
    const activeFilters = Object.entries(filters)
      .filter(([, value]) => value)
      .map(([key]) => key)
      .join(',')

    navigate(`/issues?severity=${activeFilters}`)
    setFilterOpen(false)
  }

  return (
    <header className="topbar">
      {/* Left Section - Logo */}
      <div className="topbar-left">
        <div className="topbar-logo" onClick={handleLogoClick}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
            <line x1="9" y1="9" x2="15" y2="9"></line>
            <line x1="9" y1="15" x2="15" y2="15"></line>
          </svg>
          <span>Sisyfix</span>
        </div>
      </div>

      <div className="topbar-center">
        <div className="topbar-toolbar">
          {/* Search */}
          <div className={`topbar-search ${searchOpen ? 'open' : ''}`}>
            {searchOpen ? (
              <form onSubmit={handleSearchSubmit} className="search-form">
                <input
                  ref={searchInputRef}
                  type="text"
                  placeholder="Search CVEs, assets, issues..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
                <button
                  type="button"
                  className="search-close-btn"
                  onClick={() => {
                    setSearchOpen(false)
                    setSearchQuery('')
                  }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                  </svg>
                </button>
              </form>
            ) : (
              <button
                className="topbar-tool-btn"
                onClick={() => setSearchOpen(true)}
                title="Search"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8"></circle>
                  <path d="m21 21-4.3-4.3"></path>
                </svg>
              </button>
            )}
          </div>

          {/* Filter */}
          <div className="topbar-filter-wrapper" ref={filterRef}>
            <button
              className={`topbar-tool-btn ${filterOpen ? 'active' : ''}`}
              onClick={() => setFilterOpen(!filterOpen)}
              title="Filter by Severity"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
              </svg>
            </button>

            {filterOpen && (
              <div className="topbar-filter-dropdown">
                <div className="filter-header">Filter by Severity</div>
                <label className="filter-option">
                  <input
                    type="checkbox"
                    checked={filters.critical}
                    onChange={() => handleFilterChange('critical')}
                  />
                  <span className="filter-badge critical">Critical</span>
                </label>
                <label className="filter-option">
                  <input
                    type="checkbox"
                    checked={filters.high}
                    onChange={() => handleFilterChange('high')}
                  />
                  <span className="filter-badge high">High</span>
                </label>
                <label className="filter-option">
                  <input
                    type="checkbox"
                    checked={filters.medium}
                    onChange={() => handleFilterChange('medium')}
                  />
                  <span className="filter-badge medium">Medium</span>
                </label>
                <label className="filter-option">
                  <input
                    type="checkbox"
                    checked={filters.low}
                    onChange={() => handleFilterChange('low')}
                  />
                  <span className="filter-badge low">Low</span>
                </label>
                <div className="filter-divider"></div>
                <button className="filter-apply-btn" onClick={handleApplyFilters}>
                  Apply Filters
                </button>
              </div>
            )}
          </div>

          {/* Chat */}
          <button
            className="topbar-tool-btn"
            onClick={() => navigate('/chat')}
            title="Ask Sisy"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
            </svg>
          </button>
        </div>
      </div>

      {/* Right Section - User info & Logout */}
      <div className="topbar-right">
        <button
          className="notification-btn"
          title="Alerts"
          onClick={() => navigate('/alerts')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
            <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
          </svg>
        </button>

        <div className="user-info">
          <span className="user-email">{user?.email}</span>
          <span className="user-badge">{userRole === 'admin' ? 'ADMIN' : 'USER'}</span>
        </div>

        <button className="logout-button" onClick={signOut} title="Logout">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
        </button>
      </div>
    </header>
  )
}