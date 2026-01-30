import React, { useState } from 'react';
import './Settings.css';

function Settings({ user }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/users/${user.id}/password`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ currentPassword, newPassword }),
      });

      if (response.ok) {
        setMessage('Password updated successfully');
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to update password');
      }
    } catch (err) {
      setError('Connection error. Please try again.');
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-description">Manage your account preferences</p>
        </div>
      </div>

      <div className="settings-grid">
        <div className="settings-card fade-in">
          <div className="settings-card-header">
            <h2>Profile Information</h2>
            <p>Your account details</p>
          </div>
          <div className="settings-card-body">
            <div className="info-row">
              <div className="info-label">Username</div>
              <div className="info-value">{user.username}</div>
            </div>
            <div className="info-row">
              <div className="info-label">Email</div>
              <div className="info-value">{user.email}</div>
            </div>
            <div className="info-row">
              <div className="info-label">Role</div>
              <div className="info-value">
                <span className={`role-badge ${user.isAdmin ? 'admin' : 'user'}`}>
                  {user.isAdmin ? 'Administrator' : 'User'}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="settings-card fade-in" style={{ animationDelay: '0.1s' }}>
          <div className="settings-card-header">
            <h2>Change Password</h2>
            <p>Update your account password</p>
          </div>
          <form onSubmit={handlePasswordChange} className="settings-card-body">
            {message && (
              <div className="success-message fade-in">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M13 4L6 11L3 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                {message}
              </div>
            )}

            {error && (
              <div className="error-message fade-in">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.5"/>
                  <path d="M8 4V8M8 11V12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
                {error}
              </div>
            )}

            <div className="form-group">
              <label>Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
                required
              />
            </div>

            <div className="form-group">
              <label>New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
                required
              />
            </div>

            <div className="form-group">
              <label>Confirm New Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                required
              />
            </div>

            <button type="submit" className="button-primary" style={{ marginTop: '8px' }}>
              Update Password
            </button>
          </form>
        </div>

        <div className="settings-card fade-in" style={{ animationDelay: '0.2s' }}>
          <div className="settings-card-header">
            <h2>About</h2>
            <p>Application information</p>
          </div>
          <div className="settings-card-body">
            <div className="info-row">
              <div className="info-label">Version</div>
              <div className="info-value">1.0.0</div>
            </div>
            <div className="info-row">
              <div className="info-label">Rclone</div>
              <div className="info-value">Latest</div>
            </div>
            <div className="info-row">
              <div className="info-label">Documentation</div>
              <div className="info-value">
                <a
                  href="https://rclone.org/docs/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="external-link"
                >
                  View Docs
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                    <path d="M10 3H4M10 3V9M10 3L3 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Settings;
