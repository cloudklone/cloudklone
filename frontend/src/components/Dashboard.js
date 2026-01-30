import React, { useState } from 'react';
import { Routes, Route, Link, useLocation, Navigate } from 'react-router-dom';
import Transfers from './Transfers';
import Remotes from './Remotes';
import Users from './Users';
import Settings from './Settings';
import './Dashboard.css';

function Dashboard({ user, onLogout }) {
  const location = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const navItems = [
    { path: '/', label: 'Transfers', icon: 'M8 2L2 6V14L8 18L14 14V6L8 2Z M8 7L11 9V13L8 15L5 13V9L8 7Z' },
    { path: '/remotes', label: 'Remotes', icon: 'M3 7C3 5.89543 3.89543 5 5 5H11C12.1046 5 13 5.89543 13 7V13C13 14.1046 12.1046 15 11 15H5C3.89543 15 3 14.1046 3 13V7Z M7 1H9V4H7V1Z M1 7H4V9H1V7Z M12 7H15V9H12V7Z M7 12H9V15H7V12Z' },
    ...(user.isAdmin ? [{ path: '/users', label: 'Users', icon: 'M9 3C10.6569 3 12 4.34315 12 6C12 7.65685 10.6569 9 9 9C7.34315 9 6 7.65685 6 6C6 4.34315 7.34315 3 9 3Z M9 11C12.3137 11 15 12.3431 15 14V15H3V14C3 12.3431 5.68629 11 9 11Z' }] : []),
    { path: '/settings', label: 'Settings', icon: 'M8 2C8 1.44772 8.44772 1 9 1C9.55228 1 10 1.44772 10 2V3C10.5523 3 11 3.44772 11 4C11 4.55228 10.5523 5 10 5V6C10 6.55228 9.55228 7 9 7C8.44772 7 8 6.55228 8 6V5C7.44772 5 7 4.55228 7 4C7 3.44772 7.44772 3 8 3V2Z M4 7C3.44772 7 3 7.44772 3 8V9C2.44772 9 2 9.44772 2 10C2 10.5523 2.44772 11 3 11V12C3 12.5523 3.44772 13 4 13C4.55228 13 5 12.5523 5 12V11C5.55228 11 6 10.5523 6 10C6 9.44772 5.55228 9 5 9V8C5 7.44772 4.55228 7 4 7Z M12 9C11.4477 9 11 9.44772 11 10V11C10.4477 11 10 11.4477 10 12C10 12.5523 10.4477 13 11 13V14C11 14.5523 11.4477 15 12 15C12.5523 15 13 14.5523 13 14V13C13.5523 13 14 12.5523 14 12C14 11.4477 13.5523 11 13 11V10C13 9.44772 12.5523 9 12 9Z' },
  ];

  return (
    <div className="dashboard">
      <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <svg width="32" height="32" viewBox="0 0 40 40" fill="none">
              <path d="M20 4L36 12V28L20 36L4 28V12L20 4Z" stroke="url(#gradient)" strokeWidth="2" fill="none"/>
              <path d="M20 13L28 17V25L20 29L12 25V17L20 13Z" fill="url(#gradient)"/>
              <defs>
                <linearGradient id="gradient" x1="0" y1="0" x2="40" y2="40">
                  <stop offset="0%" stopColor="#3b82f6"/>
                  <stop offset="100%" stopColor="#8b5cf6"/>
                </linearGradient>
              </defs>
            </svg>
            {!sidebarCollapsed && <span className="sidebar-title">Rclone GUI</span>}
          </div>
          <button
            className="sidebar-toggle"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <path d="M12 6L8 10L12 14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ transform: sidebarCollapsed ? 'rotate(180deg)' : 'none', transformOrigin: 'center' }}/>
            </svg>
          </button>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${location.pathname === item.path ? 'active' : ''}`}
              title={sidebarCollapsed ? item.label : ''}
            >
              <svg width="20" height="20" viewBox="0 0 16 16" fill="currentColor">
                <path d={item.icon} />
              </svg>
              {!sidebarCollapsed && <span>{item.label}</span>}
            </Link>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="user-info">
            <div className="user-avatar">
              {user.username.charAt(0).toUpperCase()}
            </div>
            {!sidebarCollapsed && (
              <div className="user-details">
                <div className="user-name">{user.username}</div>
                <div className="user-role">{user.isAdmin ? 'Administrator' : 'User'}</div>
              </div>
            )}
          </div>
          <button
            className="logout-button"
            onClick={onLogout}
            title="Logout"
          >
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <path d="M7 3H4C3.44772 3 3 3.44772 3 4V16C3 16.5523 3.44772 17 4 17H7M13 13L17 9M17 9L13 5M17 9H7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </div>
      </aside>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Transfers user={user} />} />
          <Route path="/remotes" element={<Remotes user={user} />} />
          {user.isAdmin && <Route path="/users" element={<Users user={user} />} />}
          <Route path="/settings" element={<Settings user={user} />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  );
}

export default Dashboard;
