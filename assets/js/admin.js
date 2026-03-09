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
    const connectForm = document.getElementById('firephage-connect-form');
    const disconnectButton = document.querySelector('.firephage-disconnect');
    const overviewStartScanButton = document.querySelector('.firephage-overview-start-scan');
    const overviewViewResultsButton = document.querySelector('.firephage-overview-view-results');
    const confirmModal = document.getElementById('firephage-confirm-modal');
    const confirmModalTitle = document.getElementById('firephage-confirm-modal-title');
    const confirmModalBody = document.getElementById('firephage-confirm-modal-body');
    const confirmModalSubmit = document.getElementById('firephage-confirm-modal-submit');
    let pollTimer = null;
    let scanIsRunning = false;
    let currentScanState = {};
    let findingsPage = 1;
    let findingsPageSize = 25;
    let pendingConfirmation = null;
    let selectedFindings = new Set();

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

    const closeConfirmModal = () => {
        pendingConfirmation = null;

        if (!confirmModal || !confirmModalSubmit) {
            return;
        }

        confirmModal.hidden = true;
        confirmModalSubmit.disabled = false;
    };

    const openConfirmModal = ({ title, body, onConfirm }) => {
        if (!confirmModal || !confirmModalTitle || !confirmModalBody || !confirmModalSubmit) {
            onConfirm();
            return;
        }

        pendingConfirmation = onConfirm;
        confirmModalTitle.textContent = title;
        confirmModalBody.textContent = body;
        confirmModal.hidden = false;
        confirmModalSubmit.disabled = false;
    };

    const deleteAllSuspiciousFiles = (button) => {
        button.setAttribute('disabled', 'disabled');

        request('firephage_delete_suspicious_files')
            .done((response) => {
                if (response.success) {
                    findingsPage = 1;
                    renderScanState(response.data.state);
                    showToast(response.data.message || 'Suspicious files deleted.');
                } else {
                    showToast((response.data && response.data.message) || 'Unable to delete suspicious files.', true);
                }
            })
            .fail((xhr) => {
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to delete suspicious files.', true);
            })
            .always(() => {
                button.removeAttribute('disabled');
                closeConfirmModal();
            });
    };

    const deleteSingleSuspiciousFile = (button) => {
        button.setAttribute('disabled', 'disabled');

        request('firephage_delete_suspicious_file', {
            file: button.dataset.file || '',
        })
            .done((response) => {
                if (response.success) {
                    renderScanState(response.data.state);
                    showToast(response.data.message || 'The suspicious file was deleted.');
                } else {
                    showToast((response.data && response.data.message) || 'Unable to delete the file.', true);
                }
            })
            .fail((xhr) => {
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to delete the file.', true);
            })
            .always(() => {
                button.removeAttribute('disabled');
                closeConfirmModal();
            });
    };

    const deleteSelectedSuspiciousFiles = (button) => {
        const files = Array.from(selectedFindings);

        button.setAttribute('disabled', 'disabled');

        request('firephage_delete_selected_suspicious_files', {
            files,
        })
            .done((response) => {
                if (response.success) {
                    selectedFindings = new Set();
                    renderScanState(response.data.state);
                    showToast(response.data.message || 'Selected suspicious files deleted.');
                } else {
                    showToast((response.data && response.data.message) || 'Unable to delete selected files.', true);
                }
            })
            .fail((xhr) => {
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to delete selected files.', true);
            })
            .always(() => {
                button.removeAttribute('disabled');
                closeConfirmModal();
            });
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
            return 'The scanner is idle. Start a background scan to verify repository integrity and review untrusted code paths.';
        }

        if (state.status === 'discovering') {
            return `Discovering candidate files: ${state.discovered_files} found so far.`;
        }

        if (state.status === 'completed') {
            return `Scan completed. ${state.scanned_files} files scanned, ${state.trusted_files} trusted, ${state.clean_files || 0} clean custom files, ${state.skipped_files || 0} skipped, ${state.integrity_issues} integrity mismatches, ${state.suspicious_files} suspicious.`;
        }

        if (state.status === 'failed') {
            return `Scan failed: ${state.last_error || 'Unknown error'}`;
        }

        return `Scanning ${state.scanned_files} of ${state.discovered_files} discovered files. Trusted: ${state.trusted_files}. Clean custom files: ${state.clean_files || 0}. Skipped: ${state.skipped_files || 0}. Integrity mismatches: ${state.integrity_issues}. Suspicious: ${state.suspicious_files}. Current file: ${state.current_file || 'Waiting...'}`;
    };

    const pageSizeOptions = (count) => {
        const options = [];

        [10, 25, 50, 100].forEach((option) => {
            if (count >= option || options.length === 0) {
                options.push(option);
            }
        });

        return options;
    };

    const findingsMarkup = (findings) => {
        if (!findings || findings.length === 0) {
            selectedFindings = new Set();
            return '<p class="firephage-empty">No integrity mismatches or suspicious files were flagged by the latest scan.</p>';
        }

        const rows = findings.slice().reverse();
        const availablePageSizes = pageSizeOptions(rows.length);
        if (!availablePageSizes.includes(findingsPageSize)) {
            findingsPageSize = availablePageSizes.includes(25) ? 25 : availablePageSizes[availablePageSizes.length - 1];
        }
        const totalPages = Math.max(1, Math.ceil(rows.length / findingsPageSize));
        findingsPage = Math.min(findingsPage, totalPages);
        const start = (findingsPage - 1) * findingsPageSize;
        const pagedRows = rows.slice(start, start + findingsPageSize);

        return `<div class="firephage-findings-toolbar">
            <label class="firephage-findings-rows">
                <span>Rows</span>
                <select class="firephage-findings-page-size">
                    ${availablePageSizes.map((option) => `<option value="${option}" ${findingsPageSize === option ? 'selected' : ''}>${option}</option>`).join('')}
                </select>
            </label>
            <div class="firephage-findings-actions">
                <button type="button" class="button firephage-button-danger firephage-delete-selected-suspicious-files" ${selectedFindings.size === 0 ? 'disabled' : ''}>${firephageAdmin.labels.deleteSelectedFiles}</button>
                <button type="button" class="button firephage-button-danger firephage-delete-suspicious-files">${firephageAdmin.labels.deleteSuspiciousFiles}</button>
                <button type="button" class="button button-secondary firephage-clear-findings">${firephageAdmin.labels.clearFindings}</button>
            </div>
        </div>
        <div class="firephage-finding-table-wrap">
            <table class="firephage-finding-table">
                <thead>
                    <tr>
                        <th scope="col">Select</th>
                        <th scope="col">File Path</th>
                        <th scope="col">Status</th>
                        <th scope="col">Details</th>
                        <th scope="col">Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${pagedRows.map((finding) => {
                        const status = finding.type === 'malware' ? 'Suspicious' : 'Integrity mismatch';
                        const details = [];

                        if (finding.source) {
                            details.push(`Source: ${String(finding.source).replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase())}`);
                        }

                        if (finding.confidence) {
                            details.push(`Confidence: ${String(finding.confidence).charAt(0).toUpperCase()}${String(finding.confidence).slice(1)}`);
                        }

                        if (finding.reasons && finding.reasons.length) {
                            details.push(finding.reasons.join(', '));
                        }

                        return `
                            <tr>
                                <td>${finding.type === 'malware'
                                    ? `<input type="checkbox" class="firephage-findings-select" value="${finding.file}" ${selectedFindings.has(finding.file) ? 'checked' : ''}>`
                                    : '<span class="firephage-empty">No</span>'}</td>
                                <td><code>${finding.file}</code></td>
                                <td><span class="firephage-badge firephage-badge--${finding.type === 'malware' ? 'critical' : 'warning'}">${status}</span></td>
                                <td>${details.join(' | ')}</td>
                                <td>${finding.type === 'malware'
                                    ? `<button type="button" class="button firephage-button-danger firephage-delete-finding" data-file="${finding.file}">${firephageAdmin.labels.deleteFile}</button>`
                                    : '<span class="firephage-empty">Protected</span>'}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
        <div class="firephage-findings-pagination">
            <button type="button" class="button button-secondary firephage-findings-prev" ${findingsPage === 1 ? 'disabled' : ''}>Previous</button>
            <span>Page ${findingsPage} of ${totalPages}</span>
            <button type="button" class="button button-secondary firephage-findings-next" ${findingsPage >= totalPages ? 'disabled' : ''}>Next</button>
        </div>`;
    };

    const renderScanState = (state) => {
        currentScanState = state;
        const badge = document.getElementById('firephage-scan-status-badge');
        const overviewBadge = document.getElementById('firephage-overview-scan-status-badge');
        const progressBar = document.getElementById('firephage-scan-progress-bar');
        const progressLabelNode = document.getElementById('firephage-scan-progress-label');
        const overviewSummary = document.getElementById('firephage-overview-scan-summary');
        const findings = document.getElementById('firephage-scan-findings');
        const suspiciousStat = document.querySelector('.firephage-suspicious-files-stat .firephage-stat-value');
        const progressTrack = progressBar ? progressBar.parentElement : null;
        const progress = state.discovered_files > 0 ? Math.max(5, Math.min(100, Math.floor((state.scanned_files / state.discovered_files) * 100))) : (state.status === 'completed' ? 100 : 5);
        scanIsRunning = state.status === 'discovering' || state.status === 'scanning';

        if (badge) {
            badge.className = `firephage-badge ${badgeClass(state.status)}`;
            badge.textContent = state.status.charAt(0).toUpperCase() + state.status.slice(1);
        }

        if (overviewBadge) {
            overviewBadge.className = `firephage-badge ${badgeClass(state.status)}`;
            overviewBadge.textContent = state.status.charAt(0).toUpperCase() + state.status.slice(1);
        }

        if (progressBar) {
            progressBar.style.width = `${progress}%`;
            progressBar.classList.toggle('is-active', scanIsRunning);
        }

        if (progressTrack) {
            progressTrack.classList.toggle('is-active', scanIsRunning);
        }

        if (progressLabelNode) {
            progressLabelNode.textContent = progressLabel(state);
        }

        if (overviewSummary) {
            overviewSummary.textContent = progressLabel(state);
        }

        if (findings) {
            findings.innerHTML = findingsMarkup(state.findings || []);
        }

        if (suspiciousStat) {
            suspiciousStat.textContent = `${state.suspicious_files || 0}`;
        }

        if (startScanButton) {
            startScanButton.disabled = scanIsRunning;
            startScanButton.textContent = scanIsRunning ? 'Scan Running...' : firephageAdmin.labels.startScan;
        }

        if (overviewStartScanButton) {
            overviewStartScanButton.disabled = scanIsRunning;
            overviewStartScanButton.textContent = scanIsRunning ? 'Scan Running...' : firephageAdmin.labels.overviewStartScan;
        }

        if (overviewViewResultsButton) {
            overviewViewResultsButton.hidden = !scanIsRunning;
        }

        if (state.status === 'discovering' || state.status === 'scanning') {
            schedulePoll();
        } else if (pollTimer) {
            window.clearTimeout(pollTimer);
        }
    };

    const rerenderFindings = () => {
        const findings = document.getElementById('firephage-scan-findings');

        if (findings) {
            findings.innerHTML = findingsMarkup(currentScanState.findings || []);
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

    const startBackgroundScan = (button = null) => {
        if (button) {
            button.disabled = true;
            button.textContent = firephageAdmin.labels.scanStarting;
        }

        if (startScanButton) {
            startScanButton.disabled = true;
            startScanButton.textContent = firephageAdmin.labels.scanStarting;
        }

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
                if (!scanIsRunning) {
                    if (startScanButton) {
                        startScanButton.disabled = false;
                        startScanButton.textContent = firephageAdmin.labels.startScan;
                    }

                    if (button) {
                        button.disabled = false;
                        button.textContent = firephageAdmin.labels.overviewStartScan;
                    }
                }
            });
    };

    tabButtons.forEach((button) => {
        button.addEventListener('click', () => {
            setActiveTab(button.dataset.tab);
        });
    });

    setActiveTab('overview');

    if (startScanButton) {
        startScanButton.addEventListener('click', () => {
            startBackgroundScan();
        });
    }

    if (overviewStartScanButton) {
        overviewStartScanButton.addEventListener('click', () => {
            setActiveTab('scanner');

            if (scanIsRunning) {
                return;
            }

            startBackgroundScan(overviewStartScanButton);
        });
    }

    if (overviewViewResultsButton) {
        overviewViewResultsButton.addEventListener('click', () => {
            setActiveTab('scanner');
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

    app.addEventListener('change', (event) => {
        if (event.target instanceof HTMLSelectElement && event.target.classList.contains('firephage-findings-page-size')) {
            findingsPageSize = parseInt(event.target.value, 10) || 25;
            findingsPage = 1;
            rerenderFindings();
            return;
        }

        if (event.target instanceof HTMLInputElement && event.target.classList.contains('firephage-findings-select')) {
            if (event.target.checked) {
                selectedFindings.add(event.target.value);
            } else {
                selectedFindings.delete(event.target.value);
            }

            rerenderFindings();
        }
    });

    app.addEventListener('click', (event) => {
        const target = event.target;

        if (!(target instanceof HTMLElement)) {
            return;
        }

        if (target.classList.contains('firephage-findings-prev')) {
            if (findingsPage > 1) {
                findingsPage -= 1;
                rerenderFindings();
            }

            return;
        }

        if (target.classList.contains('firephage-findings-next')) {
            findingsPage += 1;
            rerenderFindings();
            return;
        }

        if (target.classList.contains('firephage-clear-findings')) {
            target.setAttribute('disabled', 'disabled');

            request('firephage_clear_findings')
                .done((response) => {
                    if (response.success) {
                        findingsPage = 1;
                        renderScanState(response.data.state);
                        showToast(response.data.message || 'Latest findings were cleared.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to clear findings.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to clear findings.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.classList.contains('firephage-delete-suspicious-files')) {
            openConfirmModal({
                title: firephageAdmin.labels.confirmDeleteAllTitle,
                body: firephageAdmin.labels.confirmDeleteAllBody,
                onConfirm: () => deleteAllSuspiciousFiles(target),
            });
            return;
        }

        if (target.classList.contains('firephage-delete-selected-suspicious-files')) {
            openConfirmModal({
                title: firephageAdmin.labels.confirmDeleteSelectedTitle,
                body: `${firephageAdmin.labels.confirmDeleteSelectedBody} (${selectedFindings.size} selected)`,
                onConfirm: () => deleteSelectedSuspiciousFiles(target),
            });
            return;
        }

        if (target.classList.contains('firephage-delete-finding')) {
            openConfirmModal({
                title: firephageAdmin.labels.confirmDeleteTitle,
                body: firephageAdmin.labels.confirmDeleteBody,
                onConfirm: () => deleteSingleSuspiciousFile(target),
            });
            return;
        }

    });

    if (confirmModalSubmit) {
        confirmModalSubmit.addEventListener('click', () => {
            if (typeof pendingConfirmation === 'function') {
                confirmModalSubmit.disabled = true;
                pendingConfirmation();
            }
        });
    }

    if (confirmModal) {
        confirmModal.addEventListener('click', (event) => {
            const target = event.target;

            if (target instanceof HTMLElement && target.dataset.modalClose === '1') {
                closeConfirmModal();
            }
        });
    }

    try {
        currentScanState = JSON.parse(app.dataset.scanStatus || '{}');
        renderScanState(currentScanState);
    } catch (error) {
        currentScanState = { status: 'idle', discovered_files: 0, scanned_files: 0, findings: [] };
        renderScanState(currentScanState);
    }
}(jQuery));
