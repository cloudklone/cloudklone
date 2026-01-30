import React, { useState, useEffect } from 'react';
import './Remotes.css';

function Remotes({ user }) {
  const [remotes, setRemotes] = useState([]);
  const [providers, setProviders] = useState([]);
  const [showNewRemote, setShowNewRemote] = useState(false);
  const [editingRemote, setEditingRemote] = useState(null);
  const [loading, setLoading] = useState(true);
  const [testingRemote, setTestingRemote] = useState(null);

  const [formData, setFormData] = useState({
    name: '',
    type: '',
    config: {},
  });

  useEffect(() => {
    fetchRemotes();
    fetchProviders();
  }, []);

  const fetchRemotes = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/remotes', {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.ok) {
        const data = await response.json();
        setRemotes(data.remotes);
      }
    } catch (error) {
      console.error('Failed to fetch remotes:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchProviders = async () => {
    try {
      const response = await fetch('/api/providers');
      if (response.ok) {
        const data = await response.json();
        setProviders(data.providers);
      }
    } catch (error) {
      console.error('Failed to fetch providers:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const token = localStorage.getItem('token');
      const url = editingRemote ? `/api/remotes/${editingRemote.id}` : '/api/remotes';
      const method = editingRemote ? 'PUT' : 'POST';

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        setShowNewRemote(false);
        setEditingRemote(null);
        setFormData({ name: '', type: '', config: {} });
        fetchRemotes();
      }
    } catch (error) {
      console.error('Failed to save remote:', error);
    }
  };

  const deleteRemote = async (id) => {
    if (!window.confirm('Are you sure you want to delete this remote?')) {
      return;
    }

    try {
      const token = localStorage.getItem('token');
      await fetch(`/api/remotes/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });

      fetchRemotes();
    } catch (error) {
      console.error('Failed to delete remote:', error);
    }
  };

  const testConnection = async (id) => {
    setTestingRemote(id);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/remotes/${id}/test`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });

      const data = await response.json();

      if (data.success) {
        alert('Connection successful!');
      } else {
        alert(`Connection failed: ${data.error}`);
      }
    } catch (error) {
      alert('Connection test failed');
    } finally {
      setTestingRemote(null);
    }
  };

  const openEditModal = (remote) => {
    setEditingRemote(remote);
    setFormData({
      name: remote.name,
      type: remote.type,
      config: remote.config,
    });
    setShowNewRemote(true);
  };

  const selectedProvider = providers.find((p) => p.type === formData.type);

  if (loading) {
    return (
      <div className="page-loading">
        <div className="loading-spinner"></div>
      </div>
    );
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Remotes</h1>
          <p className="page-description">Configure your cloud storage connections</p>
        </div>
        <button className="button-primary" onClick={() => setShowNewRemote(true)}>
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <path d="M10 4V16M4 10H16" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
          Add Remote
        </button>
      </div>

      {remotes.length === 0 && (
        <div className="empty-state">
          <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
            <rect x="12" y="16" width="40" height="32" rx="4" stroke="currentColor" strokeWidth="2" fill="none"/>
            <path d="M20 24H44M20 32H36" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
          <h3>No remotes configured</h3>
          <p>Add your first cloud storage connection to get started</p>
        </div>
      )}

      <div className="remotes-grid">
        {remotes.map((remote) => (
          <div key={remote.id} className="remote-card fade-in">
            <div className="remote-header">
              <div className="remote-icon">
                {getProviderIcon(remote.type)}
              </div>
              <div className="remote-info">
                <h3 className="remote-name">{remote.name}</h3>
                <p className="remote-type">{getProviderName(remote.type)}</p>
              </div>
            </div>

            <div className="remote-config">
              {Object.entries(remote.config).slice(0, 3).map(([key, value]) => (
                <div key={key} className="config-item">
                  <span className="config-key">{key}:</span>
                  <span className="config-value">
                    {key.toLowerCase().includes('key') || key.toLowerCase().includes('password') || key.toLowerCase().includes('secret')
                      ? '••••••••'
                      : value.toString().substring(0, 30) + (value.toString().length > 30 ? '...' : '')}
                  </span>
                </div>
              ))}
            </div>

            <div className="remote-actions">
              <button
                className="button-test"
                onClick={() => testConnection(remote.id)}
                disabled={testingRemote === remote.id}
              >
                {testingRemote === remote.id ? (
                  <>
                    <div className="spinner-small"></div>
                    Testing...
                  </>
                ) : (
                  <>
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <path d="M8 2V8L11 11M15 8C15 11.866 11.866 15 8 15C4.13401 15 1 11.866 1 8C1 4.13401 4.13401 1 8 1C11.866 1 15 4.13401 15 8Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                    </svg>
                    Test
                  </>
                )}
              </button>
              <button className="button-icon" onClick={() => openEditModal(remote)} title="Edit">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M11 2L14 5L5 14H2V11L11 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                </svg>
              </button>
              <button className="button-icon" onClick={() => deleteRemote(remote.id)} title="Delete">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M2 4H14M6 4V2H10V4M3 4V14H13V4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>

      {showNewRemote && (
        <div className="modal-overlay" onClick={() => {
          setShowNewRemote(false);
          setEditingRemote(null);
          setFormData({ name: '', type: '', config: {} });
        }}>
          <div className="modal fade-in" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{editingRemote ? 'Edit Remote' : 'New Remote'}</h2>
              <button className="button-icon" onClick={() => {
                setShowNewRemote(false);
                setEditingRemote(null);
                setFormData({ name: '', type: '', config: {} });
              }}>
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                  <path d="M15 5L5 15M5 5L15 15" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              </button>
            </div>

            <form onSubmit={handleSubmit} className="modal-form">
              <div className="form-row">
                <div className="form-group">
                  <label>Remote Name *</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="my-remote"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Provider *</label>
                  <select
                    value={formData.type}
                    onChange={(e) => {
                      const provider = providers.find((p) => p.type === e.target.value);
                      setFormData({ ...formData, type: e.target.value, config: {} });
                    }}
                    required
                  >
                    <option value="">Select provider...</option>
                    {providers.map((provider) => (
                      <option key={provider.id} value={provider.type}>
                        {provider.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {selectedProvider && selectedProvider.fields.length > 0 && (
                <div className="form-section">
                  <h3>Configuration</h3>
                  {selectedProvider.fields.map((field) => (
                    <div key={field.name} className="form-group">
                      <label>
                        {field.label} {field.required && '*'}
                      </label>
                      {field.type === 'select' ? (
                        <select
                          value={formData.config[field.name] || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              config: { ...formData.config, [field.name]: e.target.value },
                            })
                          }
                          required={field.required}
                        >
                          <option value="">Select...</option>
                          {field.options.map((option) => (
                            <option key={option} value={option}>
                              {option}
                            </option>
                          ))}
                        </select>
                      ) : field.type === 'textarea' ? (
                        <textarea
                          value={formData.config[field.name] || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              config: { ...formData.config, [field.name]: e.target.value },
                            })
                          }
                          placeholder={field.label}
                          required={field.required}
                          rows={4}
                          style={{
                            padding: '12px 16px',
                            background: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-medium)',
                            borderRadius: '8px',
                            color: 'var(--text-primary)',
                            fontSize: '14px',
                            fontFamily: 'JetBrains Mono, monospace',
                            resize: 'vertical',
                          }}
                        />
                      ) : (
                        <input
                          type={field.type}
                          value={formData.config[field.name] || field.default || ''}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              config: { ...formData.config, [field.name]: e.target.value },
                            })
                          }
                          placeholder={field.label}
                          required={field.required}
                        />
                      )}
                    </div>
                  ))}
                </div>
              )}

              <div className="modal-actions">
                <button type="button" className="button-secondary" onClick={() => {
                  setShowNewRemote(false);
                  setEditingRemote(null);
                  setFormData({ name: '', type: '', config: {} });
                }}>
                  Cancel
                </button>
                <button type="submit" className="button-primary">
                  {editingRemote ? 'Update Remote' : 'Add Remote'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function getProviderName(type) {
  const names = {
    's3': 'Amazon S3',
    'b2': 'Backblaze B2',
    'google cloud storage': 'Google Cloud Storage',
    'azureblob': 'Azure Blob Storage',
    'dropbox': 'Dropbox',
    'drive': 'Google Drive',
    'sftp': 'SFTP',
    'local': 'Local Filesystem',
  };
  return names[type] || type;
}

function getProviderIcon(type) {
  const colors = {
    's3': 'linear-gradient(135deg, #FF9900, #FF6600)',
    'b2': 'linear-gradient(135deg, #E4002B, #FF3366)',
    'google cloud storage': 'linear-gradient(135deg, #4285F4, #34A853)',
    'azureblob': 'linear-gradient(135deg, #0078D4, #50E6FF)',
    'dropbox': 'linear-gradient(135deg, #0061FF, #00D1FF)',
    'drive': 'linear-gradient(135deg, #4285F4, #34A853, #FBBC05)',
    'sftp': 'linear-gradient(135deg, #6366F1, #8B5CF6)',
    'local': 'linear-gradient(135deg, #6B7280, #9CA3AF)',
  };

  return (
    <div
      style={{
        width: '48px',
        height: '48px',
        borderRadius: '12px',
        background: colors[type] || colors['local'],
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: 'white',
        fontWeight: '700',
        fontSize: '20px',
      }}
    >
      {getProviderName(type).charAt(0)}
    </div>
  );
}

export default Remotes;
