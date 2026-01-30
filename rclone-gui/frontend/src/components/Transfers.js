import React, { useState, useEffect } from 'react';
import './Transfers.css';

function Transfers({ user }) {
  const [transfers, setTransfers] = useState([]);
  const [remotes, setRemotes] = useState([]);
  const [showNewTransfer, setShowNewTransfer] = useState(false);
  const [loading, setLoading] = useState(true);
  const [ws, setWs] = useState(null);

  const [formData, setFormData] = useState({
    sourceRemote: '',
    sourcePath: '/',
    destRemote: '',
    destPath: '/',
    operation: 'copy',
  });

  useEffect(() => {
    fetchTransfers();
    fetchRemotes();
    connectWebSocket();

    return () => {
      if (ws) ws.close();
    };
  }, []);

  const connectWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      console.log('WebSocket connected');
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === 'transfer_update' || data.type === 'transfer_progress') {
        setTransfers((prev) =>
          prev.map((t) =>
            t.transfer_id === data.transferId || t.transfer_id === data.transfer?.transfer_id
              ? { ...t, ...data.transfer, progress: data.progress || t.progress }
              : t
          )
        );
      } else if (data.type === 'transfer_complete' || data.type === 'transfer_failed') {
        fetchTransfers();
      }
    };

    socket.onclose = () => {
      console.log('WebSocket disconnected, reconnecting...');
      setTimeout(connectWebSocket, 5000);
    };

    setWs(socket);
  };

  const fetchTransfers = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/transfers', {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.ok) {
        const data = await response.json();
        setTransfers(data.transfers);
      }
    } catch (error) {
      console.error('Failed to fetch transfers:', error);
    } finally {
      setLoading(false);
    }
  };

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
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('/api/transfers', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        setShowNewTransfer(false);
        setFormData({
          sourceRemote: '',
          sourcePath: '/',
          destRemote: '',
          destPath: '/',
          operation: 'copy',
        });
        fetchTransfers();
      }
    } catch (error) {
      console.error('Failed to create transfer:', error);
    }
  };

  const deleteTransfer = async (transferId) => {
    try {
      const token = localStorage.getItem('token');
      await fetch(`/api/transfers/${transferId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });

      fetchTransfers();
    } catch (error) {
      console.error('Failed to delete transfer:', error);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'running':
        return (
          <div className="status-icon running">
            <div className="spinner-small"></div>
          </div>
        );
      case 'completed':
        return (
          <div className="status-icon completed">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M13 4L6 11L3 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
        );
      case 'failed':
        return (
          <div className="status-icon failed">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M12 4L4 12M4 4L12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
        );
      default:
        return (
          <div className="status-icon queued">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="2"/>
            </svg>
          </div>
        );
    }
  };

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
          <h1 className="page-title">Transfers</h1>
          <p className="page-description">Monitor and manage your data transfers</p>
        </div>
        <button className="button-primary" onClick={() => setShowNewTransfer(true)}>
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <path d="M10 4V16M4 10H16" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
          New Transfer
        </button>
      </div>

      {remotes.length === 0 && (
        <div className="empty-state">
          <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
            <path d="M32 8L56 20V44L32 56L8 44V20L32 8Z" stroke="currentColor" strokeWidth="2" fill="none"/>
            <path d="M32 22L44 28V40L32 46L20 40V28L32 22Z" fill="currentColor" opacity="0.2"/>
          </svg>
          <h3>No remotes configured</h3>
          <p>Add a remote connection before creating transfers</p>
        </div>
      )}

      {transfers.length === 0 && remotes.length > 0 && (
        <div className="empty-state">
          <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
            <path d="M16 24H48M16 32H48M16 40H32" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
          <h3>No transfers yet</h3>
          <p>Create your first transfer to get started</p>
        </div>
      )}

      <div className="transfers-grid">
        {transfers.map((transfer) => (
          <div key={transfer.id} className="transfer-card fade-in">
            <div className="transfer-header">
              <div className="transfer-status">
                {getStatusIcon(transfer.status)}
                <span className={`status-text ${transfer.status}`}>
                  {transfer.status.charAt(0).toUpperCase() + transfer.status.slice(1)}
                </span>
              </div>
              <div className="transfer-operation">
                {transfer.operation === 'copy' ? 'Copy' : 'Sync'}
              </div>
            </div>

            <div className="transfer-paths">
              <div className="path-item">
                <div className="path-label">Source</div>
                <div className="path-value">
                  <code>{transfer.source_remote}:{transfer.source_path}</code>
                </div>
              </div>
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className="arrow-icon">
                <path d="M4 10H16M16 10L11 5M16 10L11 15" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <div className="path-item">
                <div className="path-label">Destination</div>
                <div className="path-value">
                  <code>{transfer.dest_remote}:{transfer.dest_path}</code>
                </div>
              </div>
            </div>

            {transfer.progress && transfer.status === 'running' && (
              <div className="transfer-progress">
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{ width: `${transfer.progress.percentage || 0}%` }}
                  ></div>
                </div>
                <div className="progress-stats">
                  <span>{transfer.progress.transferred || '0 B'}</span>
                  <span>{transfer.progress.speed || '0 B/s'}</span>
                  <span>ETA: {transfer.progress.eta || 'calculating...'}</span>
                </div>
              </div>
            )}

            {transfer.error && (
              <div className="transfer-error">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <circle cx="8" cy="8" r="7" stroke="currentColor" strokeWidth="1.5"/>
                  <path d="M8 4V8M8 11V12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
                {transfer.error}
              </div>
            )}

            <div className="transfer-footer">
              <div className="transfer-time">
                {new Date(transfer.created_at).toLocaleString()}
              </div>
              <button
                className="button-icon"
                onClick={() => deleteTransfer(transfer.transfer_id)}
                title="Delete transfer"
              >
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M2 4H14M6 4V2H10V4M3 4V14H13V4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>

      {showNewTransfer && (
        <div className="modal-overlay" onClick={() => setShowNewTransfer(false)}>
          <div className="modal fade-in" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>New Transfer</h2>
              <button className="button-icon" onClick={() => setShowNewTransfer(false)}>
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                  <path d="M15 5L5 15M5 5L15 15" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              </button>
            </div>

            <form onSubmit={handleSubmit} className="modal-form">
              <div className="form-row">
                <div className="form-group">
                  <label>Operation</label>
                  <select
                    value={formData.operation}
                    onChange={(e) => setFormData({ ...formData, operation: e.target.value })}
                  >
                    <option value="copy">Copy (preserve source)</option>
                    <option value="sync">Sync (mirror to destination)</option>
                  </select>
                </div>
              </div>

              <div className="form-section">
                <h3>Source</h3>
                <div className="form-row">
                  <div className="form-group">
                    <label>Remote</label>
                    <select
                      value={formData.sourceRemote}
                      onChange={(e) => setFormData({ ...formData, sourceRemote: e.target.value })}
                      required
                    >
                      <option value="">Select remote...</option>
                      {remotes.map((remote) => (
                        <option key={remote.id} value={remote.name}>
                          {remote.name} ({remote.type})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Path</label>
                    <input
                      type="text"
                      value={formData.sourcePath}
                      onChange={(e) => setFormData({ ...formData, sourcePath: e.target.value })}
                      placeholder="/"
                      required
                    />
                  </div>
                </div>
              </div>

              <div className="form-section">
                <h3>Destination</h3>
                <div className="form-row">
                  <div className="form-group">
                    <label>Remote</label>
                    <select
                      value={formData.destRemote}
                      onChange={(e) => setFormData({ ...formData, destRemote: e.target.value })}
                      required
                    >
                      <option value="">Select remote...</option>
                      {remotes.map((remote) => (
                        <option key={remote.id} value={remote.name}>
                          {remote.name} ({remote.type})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group">
                    <label>Path</label>
                    <input
                      type="text"
                      value={formData.destPath}
                      onChange={(e) => setFormData({ ...formData, destPath: e.target.value })}
                      placeholder="/"
                      required
                    />
                  </div>
                </div>
              </div>

              <div className="modal-actions">
                <button type="button" className="button-secondary" onClick={() => setShowNewTransfer(false)}>
                  Cancel
                </button>
                <button type="submit" className="button-primary">
                  Start Transfer
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default Transfers;
