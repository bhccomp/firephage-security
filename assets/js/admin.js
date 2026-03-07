(function ($) {
    'use strict';

    const app = document.getElementById('firephage-admin-app');

    if (!app || typeof firephageAdmin === 'undefined') {
        return;
    }

    const toast = document.getElementById('firephage-toast');
    const tabButtons = Array.from(document.querySelectorAll('.firephage-tab-button'));
    const tabPanels = Array.from(document.querySelectorAll('.firephage-tab-panel'));
    const startScanButton = document.querySelector('.firephage-start-scan');
    const refreshHealthButton = document.querySelector('.firephage-refresh-health');
    const syncReportButton = document.querySelector('.firephage-sync-report');
    const connectForm = document.getElementById('firephage-connect-form');
    const disconnectButton = document.querySelector('.firephage-disconnect');
    let pollTimer = null;

    const request = (action, payload = {}) => $.post(firephageAdmin.ajaxUrl, {
        action,
        nonce: firephageAdmin.nonce,
        ...payload,
    });

    const showToast = (message, isError = false) => {
        if (!toast) {
            return;
        }

        toast.textContent = message;
        toast.hidden = false;
        toast.classList.toggle('is-error', isError);

        window.clearTimeout(showToast.timer);
        showToast.timer = window.setTimeout(() => {
            toast.hidden = true;
        }, 3200);
    };

    const setActiveTab = (tabId) => {
        tabButtons.forEach((button) => {
            button.classList.toggle('is-active', button.dataset.tab === tabId);
        });

        tabPanels.forEach((panel) => {
            panel.hidden = panel.dataset.panel !== tabId;
        });
    };

    const badgeClass = (status) => {
        if (status === 'completed') {
            return 'firephage-badge--good';
        }

        if (status === 'failed') {
            return 'firephage-badge--critical';
        }

        if (status === 'discovering' || status === 'scanning') {
            return 'firephage-badge--warning';
        }

        return 'firephage-badge--neutral';
    };

    const progressLabel = (state) => {
        if (state.status === 'idle') {
            return 'The scanner is idle. Start a background scan to inspect PHP and JavaScript files.';
        }

        if (state.status === 'discovering') {
            return `Discovering candidate files: ${state.discovered_files} found so far.`;
        }

        if (state.status === 'completed') {
            return `Scan completed. ${state.scanned_files} files scanned, ${state.suspicious_files} suspicious files flagged.`;
        }

        if (state.status === 'failed') {
            return `Scan failed: ${state.last_error || 'Unknown error'}`;
        }

        return `Scanning ${state.scanned_files} of ${state.discovered_files} discovered files. Current file: ${state.current_file || 'Waiting...'}`;
    };

    const findingsMarkup = (findings) => {
        if (!findings || findings.length === 0) {
            return '<p class="firephage-empty">No suspicious files flagged by the latest scan.</p>';
        }

        return `<div class="firephage-finding-list">${findings.slice().reverse().map((finding) => `
            <div class="firephage-finding">
                <strong><code>${finding.file}</code></strong>
                <span>${(finding.reasons || []).join(', ')}</span>
            </div>
        `).join('')}</div>`;
    };

    const renderScanState = (state) => {
        const badge = document.getElementById('firephage-scan-status-badge');
        const progressBar = document.getElementById('firephage-scan-progress-bar');
        const progressLabelNode = document.getElementById('firephage-scan-progress-label');
        const findings = document.getElementById('firephage-scan-findings');
        const progress = state.discovered_files > 0 ? Math.max(5, Math.min(100, Math.floor((state.scanned_files / state.discovered_files) * 100))) : (state.status === 'completed' ? 100 : 5);

        if (badge) {
            badge.className = `firephage-badge ${badgeClass(state.status)}`;
            badge.textContent = state.status.charAt(0).toUpperCase() + state.status.slice(1);
        }

        if (progressBar) {
            progressBar.style.width = `${progress}%`;
        }

        if (progressLabelNode) {
            progressLabelNode.textContent = progressLabel(state);
        }

        if (findings) {
            findings.innerHTML = findingsMarkup(state.findings || []);
        }

        if (state.status === 'discovering' || state.status === 'scanning') {
            schedulePoll();
        } else if (pollTimer) {
            window.clearTimeout(pollTimer);
        }
    };

    const renderHealth = (report) => {
        const healthChecks = document.getElementById('firephage-health-checks');
        const checksumNode = document.getElementById('firephage-core-checksum');

        if (healthChecks && report.health && report.health.checks) {
            healthChecks.innerHTML = report.health.checks.map((check) => `
                <div class="firephage-card">
                    <div class="firephage-card-head">
                        <h3>${check.label}</h3>
                        <span class="firephage-badge firephage-badge--${check.status}">${check.status.charAt(0).toUpperCase() + check.status.slice(1)}</span>
                    </div>
                    <p>${check.message}</p>
                </div>
            `).join('');
        }

        if (checksumNode && report.health && report.health.core_checksum) {
            const checksum = report.health.core_checksum;
            checksumNode.innerHTML = `
                <div class="firephage-card-head">
                    <h3>WordPress Core Checksums</h3>
                    <span class="firephage-badge firephage-badge--${checksum.status}">${checksum.status.charAt(0).toUpperCase() + checksum.status.slice(1)}</span>
                </div>
                <p>${checksum.summary}</p>
                ${checksum.modified && checksum.modified.length ? `<div class="firephage-checksum-list"><h4>Modified files</h4><ul class="firephage-list">${checksum.modified.map((item) => `<li><code>${item}</code></li>`).join('')}</ul></div>` : ''}
                ${checksum.missing && checksum.missing.length ? `<div class="firephage-checksum-list"><h4>Missing files</h4><ul class="firephage-list">${checksum.missing.map((item) => `<li><code>${item}</code></li>`).join('')}</ul></div>` : ''}
            `;
        }
    };

    const schedulePoll = () => {
        if (pollTimer) {
            window.clearTimeout(pollTimer);
        }

        pollTimer = window.setTimeout(() => {
            request('firephage_scan_status')
                .done((response) => {
                    if (response.success) {
                        renderScanState(response.data.state);
                    }
                });
        }, 3000);
    };

    tabButtons.forEach((button) => {
        button.addEventListener('click', () => {
            setActiveTab(button.dataset.tab);
        });
    });

    setActiveTab('overview');

    if (startScanButton) {
        startScanButton.addEventListener('click', () => {
            startScanButton.disabled = true;
            startScanButton.textContent = firephageAdmin.labels.scanStarting;

            request('firephage_start_scan')
                .done((response) => {
                    if (response.success) {
                        renderScanState(response.data.state);
                        showToast('Background malware scan started.');
                    } else {
                        showToast(response.data.message || 'Unable to start the scan.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to start the scan.', true);
                })
                .always(() => {
                    startScanButton.disabled = false;
                    startScanButton.textContent = firephageAdmin.labels.startScan;
                });
        });
    }

    if (refreshHealthButton) {
        refreshHealthButton.addEventListener('click', () => {
            refreshHealthButton.disabled = true;

            request('firephage_refresh_health')
                .done((response) => {
                    if (response.success) {
                        renderHealth(response.data.report);
                        showToast('Health checks refreshed.');
                    }
                })
                .always(() => {
                    refreshHealthButton.disabled = false;
                });
        });
    }

    if (syncReportButton) {
        syncReportButton.addEventListener('click', () => {
            syncReportButton.disabled = true;
            syncReportButton.textContent = firephageAdmin.labels.syncing;

            request('firephage_sync_report')
                .done((response) => {
                    showToast(response.data.message || 'Report sent.');
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to send report.', true);
                })
                .always(() => {
                    syncReportButton.disabled = false;
                    syncReportButton.textContent = firephageAdmin.labels.syncReport;
                });
        });
    }

    if (connectForm) {
        connectForm.addEventListener('submit', (event) => {
            event.preventDefault();

            const formData = new window.FormData(connectForm);

            request('firephage_connect_dashboard', {
                dashboard_url: formData.get('dashboard_url'),
                connection_token: formData.get('connection_token'),
                auto_sync_reports: formData.get('auto_sync_reports') ? '1' : '',
            })
                .done((response) => {
                    const siteId = document.getElementById('firephage-connected-site-id');

                    if (siteId && response.data.settings && response.data.settings.site_id) {
                        siteId.textContent = response.data.settings.site_id;
                    }

                    const tokenInput = connectForm.querySelector('input[name="connection_token"]');

                    if (tokenInput) {
                        tokenInput.value = '';
                    }

                    showToast(response.data.message || 'Plugin connected.');
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to connect the plugin.', true);
                });
        });
    }

    if (disconnectButton) {
        disconnectButton.addEventListener('click', () => {
            request('firephage_disconnect_dashboard')
                .done((response) => {
                    const siteId = document.getElementById('firephage-connected-site-id');

                    if (siteId) {
                        siteId.textContent = firephageAdmin.labels.notConnected;
                    }

                    showToast(response.data.message || 'Plugin disconnected.');
                })
                .fail(() => {
                    showToast('Unable to disconnect the plugin.', true);
                });
        });
    }

    try {
        renderScanState(JSON.parse(app.dataset.scanStatus || '{}'));
    } catch (error) {
        renderScanState({ status: 'idle', discovered_files: 0, scanned_files: 0, findings: [] });
    }
}(jQuery));
