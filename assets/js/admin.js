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
    const bruteForceForm = document.getElementById('firephage-bruteforce-form');
    const clearBruteForceLockoutsButton = document.querySelector('.firephage-clear-bruteforce-lockouts');
    const connectForm = document.getElementById('firephage-connect-form');
    const disconnectButton = document.querySelector('.firephage-disconnect');
    const overviewStartScanButton = document.querySelector('.firephage-overview-start-scan');
    const overviewNewScanButton = document.querySelector('.firephage-overview-new-scan');
    const overviewViewResultsButton = document.querySelector('.firephage-overview-view-results');
    const stopScanButton = document.querySelector('.firephage-stop-scan');
    const startNewScanButton = document.querySelector('.firephage-start-new-scan');
    const confirmModal = document.getElementById('firephage-confirm-modal');
    const confirmModalTitle = document.getElementById('firephage-confirm-modal-title');
    const confirmModalBody = document.getElementById('firephage-confirm-modal-body');
    const confirmModalSubmit = document.getElementById('firephage-confirm-modal-submit');
    const previewModal = document.getElementById('firephage-preview-modal');
    const previewModalTitle = document.getElementById('firephage-preview-modal-title');
    const previewModalMeta = document.getElementById('firephage-preview-modal-meta');
    const previewModalContent = document.getElementById('firephage-preview-modal-content');
    const firewallStatusBadge = document.getElementById('firephage-firewall-status-badge');
    const firewallSummaryText = document.getElementById('firephage-firewall-summary-text');
    const firewallConnectionNote = document.getElementById('firephage-firewall-connection-note');
    const firewallRequestsBlocked = document.getElementById('firephage-firewall-requests-blocked');
    const firewallChallengeRate = document.getElementById('firephage-firewall-challenge-rate');
    const firewallBotPressure = document.getElementById('firephage-firewall-bot-pressure');
    const firewallActivityBody = document.getElementById('firephage-firewall-activity-body');
    const firewallProtectionMode = document.getElementById('firephage-firewall-protection-mode');
    const firewallTrustedIps = document.getElementById('firephage-firewall-trusted-ips');
    const firewallCountryBlocks = document.getElementById('firephage-firewall-country-blocks');
    const firewallUpgradeCard = document.getElementById('firephage-firewall-upgrade-card');
    const performanceStatusBadge = document.getElementById('firephage-performance-status-badge');
    const performanceSummaryText = document.getElementById('firephage-performance-summary-text');
    const performanceConnectionNote = document.getElementById('firephage-performance-connection-note');
    const performanceHostname = document.getElementById('firephage-performance-hostname');
    const performanceImageOptimization = document.getElementById('firephage-performance-image-optimization');
    const performanceEdgeCompression = document.getElementById('firephage-performance-edge-compression');
    const performanceCacheRules = document.getElementById('firephage-performance-cache-rules');
    const performanceUpgradeCard = document.getElementById('firephage-performance-upgrade-card');
    const bruteForceOverviewBadge = document.getElementById('firephage-bruteforce-overview-badge');
    const bruteForceOverviewSummary = document.getElementById('firephage-bruteforce-overview-summary');
    const bruteForceStatusBadge = document.getElementById('firephage-bruteforce-status-badge');
    const bruteForceSummaryText = document.getElementById('firephage-bruteforce-summary-text');
    const bruteForceThreshold = document.getElementById('firephage-bruteforce-threshold');
    const bruteForceWindow = document.getElementById('firephage-bruteforce-window');
    const bruteForceActiveCount = document.getElementById('firephage-bruteforce-active-count');
    const bruteForceXmlrpcNote = document.getElementById('firephage-bruteforce-xmlrpc-note');
    const bruteForceActiveBadge = document.getElementById('firephage-bruteforce-active-lockouts-badge');
    const bruteForceActiveLockouts = document.getElementById('firephage-bruteforce-active-lockouts');
    const bruteForceRecentEvents = document.getElementById('firephage-bruteforce-recent-events');
    let pollTimer = null;
    let scanIsRunning = false;
    let currentScanState = {};
    let findingsPage = 1;
    let findingsPageSize = 25;
    let pendingConfirmation = null;
    let selectedFindings = new Set();
    let proTabState = {
        firewallLoaded: false,
        performanceLoaded: false,
    };

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

    const closePreviewModal = () => {
        if (!previewModal || !previewModalMeta || !previewModalContent) {
            return;
        }

        previewModal.hidden = true;
        previewModalMeta.textContent = '';
        previewModalContent.textContent = '';
    };

    const openPreviewModal = ({ file, content, truncated }) => {
        if (!previewModal || !previewModalTitle || !previewModalMeta || !previewModalContent) {
            return;
        }

        previewModalTitle.textContent = firephageAdmin.labels.previewFile || 'File Preview';
        previewModalMeta.textContent = truncated
            ? `${file} • Preview truncated to keep the browser responsive.`
            : file;
        previewModalContent.textContent = content || '';
        previewModal.hidden = false;
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

    const setBadge = (node, text, tone = 'neutral') => {
        if (!node) {
            return;
        }

        node.className = `firephage-badge firephage-badge--${tone}`;
        node.textContent = text;
    };

    const renderFirewallSummary = (payload) => {
        if (!firewallSummaryText || !firewallConnectionNote) {
            return;
        }

        if (!payload.connected) {
            setBadge(firewallStatusBadge, 'Connect', 'neutral');
            firewallSummaryText.textContent = firephageAdmin.labels.connectRequired;
            firewallConnectionNote.textContent = payload.message || firephageAdmin.labels.connectRequired;
            return;
        }

        const statusTone = payload.pro_enabled ? 'good' : 'warning';
        setBadge(firewallStatusBadge, payload.pro_enabled ? 'Live' : 'Plan Required', statusTone);
        firewallSummaryText.textContent = `${payload.status.label} on ${payload.site.domain}. WAF status: ${payload.status.waf_status}.`;
        firewallConnectionNote.textContent = payload.pro_enabled ? 'Live firewall telemetry is loaded from your connected FirePhage site.' : firephageAdmin.labels.proInactive;

        if (firewallRequestsBlocked) {
            firewallRequestsBlocked.textContent = `${payload.metrics.requests_blocked || 0}`;
        }

        if (firewallChallengeRate) {
            firewallChallengeRate.textContent = `${payload.metrics.challenge_rate || 0}%`;
        }

        if (firewallBotPressure) {
            firewallBotPressure.textContent = `${payload.metrics.bot_pressure || 0}%`;
        }

        if (firewallProtectionMode) {
            firewallProtectionMode.innerHTML = `<option>${payload.controls.protection_mode || 'Adaptive WAF'}</option>`;
        }

        if (firewallTrustedIps) {
            firewallTrustedIps.value = payload.controls.trusted_ips || 'No managed allowlist entries yet';
        }

        if (firewallCountryBlocks) {
            firewallCountryBlocks.value = payload.controls.country_blocks || 'No managed country blocks';
        }

        if (firewallActivityBody && Array.isArray(payload.activity)) {
            firewallActivityBody.innerHTML = payload.activity.length
                ? payload.activity.map((row) => `<div class="firephage-pro-table__row"><span>${row.timestamp ? new Date(row.timestamp).toLocaleString() : '--'}</span><span>${row.action || 'ALLOW'}</span><span>${row.path || '/'}</span></div>`).join('')
                : '<div class="firephage-pro-table__row"><span>--</span><span>No activity yet</span><span>/</span></div>';
        }

        if (firewallUpgradeCard) {
            firewallUpgradeCard.style.display = payload.pro_enabled ? 'none' : '';
        }
    };

    const renderPerformanceSummary = (payload) => {
        if (!performanceSummaryText || !performanceConnectionNote) {
            return;
        }

        if (!payload.connected) {
            setBadge(performanceStatusBadge, 'Connect', 'neutral');
            performanceSummaryText.textContent = firephageAdmin.labels.connectRequired;
            performanceConnectionNote.textContent = payload.message || firephageAdmin.labels.connectRequired;
            return;
        }

        const tone = payload.pro_enabled ? 'good' : 'warning';
        setBadge(performanceStatusBadge, payload.pro_enabled ? 'Live' : 'Plan Required', tone);
        performanceSummaryText.textContent = `${payload.summary.requests_24h || 0} requests over the last 24 hours. Cache hit ratio: ${payload.summary.cache_hit_ratio || 0}%.`;
        performanceConnectionNote.textContent = payload.pro_enabled ? 'Live CDN and cache telemetry is loaded from your connected FirePhage site.' : firephageAdmin.labels.proInactive;

        if (performanceHostname) {
            performanceHostname.value = payload.summary.edge_hostname || 'No edge hostname yet';
        }

        if (performanceImageOptimization) {
            performanceImageOptimization.checked = !!payload.settings.smart_image_optimization;
        }

        if (performanceEdgeCompression) {
            performanceEdgeCompression.checked = !!payload.settings.edge_compression;
        }

        if (performanceCacheRules && Array.isArray(payload.cache_rules)) {
            performanceCacheRules.innerHTML = payload.cache_rules.length
                ? payload.cache_rules.map((rule) => `<div class="firephage-pro-table__row"><span>${rule.path}</span><span>${rule.behavior}</span><span>${rule.state}</span></div>`).join('')
                : '<div class="firephage-pro-table__row"><span>--</span><span>No managed cache rules yet</span><span>--</span></div>';
        }

        if (performanceUpgradeCard) {
            performanceUpgradeCard.style.display = payload.pro_enabled ? 'none' : '';
        }
    };

    const bruteForceRowsMarkup = (rows, showRemaining = false) => {
        if (!rows || rows.length === 0) {
            return '<p class="firephage-empty">No entries to show right now.</p>';
        }

        return `<div class="firephage-finding-table-wrap firephage-finding-table-wrap--compact">
            <table class="firephage-finding-table firephage-finding-table--auto">
                <thead>
                    <tr>
                        <th scope="col">Username</th>
                        <th scope="col">IP</th>
                        <th scope="col">Surface</th>
                        <th scope="col">Attempts</th>
                        <th scope="col">Started</th>
                        <th scope="col">Expires</th>
                        ${showRemaining ? '<th scope="col">Remaining</th>' : ''}
                    </tr>
                </thead>
                <tbody>
                    ${rows.map((row) => `<tr>
                        <td>${row.username || 'Any username'}</td>
                        <td><code>${row.ip || 'unknown'}</code></td>
                        <td>${String(row.surface || 'login').toUpperCase()}</td>
                        <td>${row.failed_attempts || 0}</td>
                        <td>${row.started_at || ''}</td>
                        <td>${row.expires_at || ''}</td>
                        ${showRemaining ? `<td>${row.remaining || 0} min</td>` : ''}
                    </tr>`).join('')}
                </tbody>
            </table>
        </div>`;
    };

    const renderBruteForceSummary = (summary) => {
        if (!summary) {
            return;
        }

        const badgeTone = summary.status || 'neutral';
        const overviewText = !summary.enabled ? 'Disabled' : ((summary.active_lockouts_count || 0) > 0 ? 'Active Lockouts' : 'Enabled');

        setBadge(bruteForceOverviewBadge, overviewText, badgeTone);
        setBadge(bruteForceStatusBadge, summary.enabled ? 'Enabled' : 'Disabled', badgeTone);

        if (bruteForceOverviewSummary) {
            bruteForceOverviewSummary.textContent = summary.summary || '';
        }

        if (bruteForceSummaryText) {
            bruteForceSummaryText.textContent = summary.summary || '';
        }

        if (bruteForceThreshold) {
            bruteForceThreshold.textContent = `${summary.threshold || 0}`;
        }

        if (bruteForceWindow) {
            bruteForceWindow.textContent = `${summary.window_minutes || 0}m / ${summary.lockout_minutes || 0}m`;
        }

        if (bruteForceActiveCount) {
            bruteForceActiveCount.textContent = `${summary.active_lockouts_count || 0}`;
        }

        if (bruteForceXmlrpcNote) {
            bruteForceXmlrpcNote.textContent = summary.protect_xmlrpc
                ? 'XML-RPC authentication is currently covered by the same rate-limit rules.'
                : 'XML-RPC authentication is currently excluded from local brute-force protection.';
        }

        if (bruteForceActiveBadge) {
            setBadge(bruteForceActiveBadge, `${summary.active_lockouts_count || 0} active`, (summary.active_lockouts_count || 0) > 0 ? 'warning' : 'neutral');
        }

        if (bruteForceActiveLockouts && Array.isArray(summary.active_lockouts)) {
            bruteForceActiveLockouts.innerHTML = bruteForceRowsMarkup(summary.active_lockouts || [], true);
        }

        if (bruteForceRecentEvents && Array.isArray(summary.recent_events)) {
            bruteForceRecentEvents.innerHTML = bruteForceRowsMarkup(summary.recent_events || [], false);
        }
    };

    const maybeLoadProTab = (tabId) => {
        if (tabId === 'firewall' && !proTabState.firewallLoaded) {
            proTabState.firewallLoaded = true;
            renderFirewallSummary({ connected: false, message: firephageAdmin.labels.loadingProData });
            request('firephage_fetch_firewall_summary')
                .done((response) => {
                    if (response.success) {
                        renderFirewallSummary(response.data);
                    } else {
                        proTabState.firewallLoaded = false;
                        showToast((response.data && response.data.message) || 'Unable to load firewall data.', true);
                    }
                })
                .fail((xhr) => {
                    proTabState.firewallLoaded = false;
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to load firewall data.', true);
                });
        }

        if (tabId === 'performance' && !proTabState.performanceLoaded) {
            proTabState.performanceLoaded = true;
            renderPerformanceSummary({ connected: false, message: firephageAdmin.labels.loadingProData });
            request('firephage_fetch_performance_summary')
                .done((response) => {
                    if (response.success) {
                        renderPerformanceSummary(response.data);
                    } else {
                        proTabState.performanceLoaded = false;
                        showToast((response.data && response.data.message) || 'Unable to load performance data.', true);
                    }
                })
                .fail((xhr) => {
                    proTabState.performanceLoaded = false;
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to load performance data.', true);
                });
        }
    };

    const setActiveTab = (tabId) => {
        tabButtons.forEach((button) => {
            button.classList.toggle('is-active', button.dataset.tab === tabId);
        });

        tabPanels.forEach((panel) => {
            panel.hidden = panel.dataset.panel !== tabId;
        });

        maybeLoadProTab(tabId);
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

        if (state.status === 'stopped') {
            return `Scan cancelled at ${state.scanned_files} of ${state.discovered_files} discovered files. Trusted: ${state.trusted_files}. Clean custom files: ${state.clean_files || 0}. Skipped: ${state.skipped_files || 0}. Integrity mismatches: ${state.integrity_issues}. Suspicious: ${state.suspicious_files}. Use Resume Scan to continue from the saved position.`;
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
                                    ? `<div class="firephage-row-actions"><button type="button" class="button button-secondary firephage-preview-file" data-file="${finding.file}">${firephageAdmin.labels.previewFile}</button><button type="button" class="button firephage-button-danger firephage-delete-finding" data-file="${finding.file}">${firephageAdmin.labels.deleteFile}</button></div>`
                                    : `<div class="firephage-row-actions"><button type="button" class="button button-secondary firephage-preview-file" data-file="${finding.file}">${firephageAdmin.labels.previewFile}</button><span class="firephage-empty">Protected</span></div>`}</td>
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
            startScanButton.textContent = scanIsRunning
                ? 'Scan Running...'
                : (state.status === 'stopped' ? firephageAdmin.labels.resumeScan : firephageAdmin.labels.startScan);
        }

        if (overviewStartScanButton) {
            overviewStartScanButton.disabled = scanIsRunning;
            overviewStartScanButton.textContent = scanIsRunning
                ? 'Scan Running...'
                : (state.status === 'stopped' ? firephageAdmin.labels.overviewResumeScan : firephageAdmin.labels.overviewStartScan);
        }

        if (overviewViewResultsButton) {
            overviewViewResultsButton.style.display = scanIsRunning ? '' : 'none';
        }

        if (startNewScanButton) {
            startNewScanButton.style.display = state.status === 'stopped' ? '' : 'none';
            startNewScanButton.disabled = scanIsRunning;
        }

        if (overviewNewScanButton) {
            overviewNewScanButton.style.display = state.status === 'stopped' ? '' : 'none';
            overviewNewScanButton.disabled = scanIsRunning;
        }

        if (stopScanButton) {
            stopScanButton.style.display = scanIsRunning ? '' : 'none';
            stopScanButton.disabled = !scanIsRunning;
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

    const startBackgroundScan = (button = null, forceNew = false) => {
        const resumingScan = currentScanState.status === 'stopped';
        const startingFresh = forceNew;

        if (button) {
            button.disabled = true;
            button.textContent = (resumingScan && !startingFresh) ? firephageAdmin.labels.scanResuming : firephageAdmin.labels.scanStarting;
        }

        if (startScanButton) {
            startScanButton.disabled = true;
            startScanButton.textContent = (resumingScan && !startingFresh) ? firephageAdmin.labels.scanResuming : firephageAdmin.labels.scanStarting;
        }

        if (startNewScanButton) {
            startNewScanButton.disabled = true;
        }

        if (overviewNewScanButton) {
            overviewNewScanButton.disabled = true;
        }

        request('firephage_start_scan', {
            force_new: forceNew ? '1' : '',
        })
            .done((response) => {
                if (response.success) {
                    renderScanState(response.data.state);
                    showToast(startingFresh ? 'A new background malware scan started.' : (resumingScan ? 'Background malware scan resumed.' : 'Background malware scan started.'));
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
                        startScanButton.textContent = currentScanState.status === 'stopped' ? firephageAdmin.labels.resumeScan : firephageAdmin.labels.startScan;
                    }

                    if (button) {
                        button.disabled = false;
                        button.textContent = currentScanState.status === 'stopped' ? firephageAdmin.labels.overviewResumeScan : firephageAdmin.labels.overviewStartScan;
                    }

                    if (startNewScanButton) {
                        startNewScanButton.disabled = false;
                    }

                    if (overviewNewScanButton) {
                        overviewNewScanButton.disabled = false;
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

    if (startNewScanButton) {
        startNewScanButton.addEventListener('click', () => {
            startBackgroundScan(startNewScanButton, true);
        });
    }

    if (stopScanButton) {
        stopScanButton.addEventListener('click', () => {
            stopScanButton.disabled = true;

            request('firephage_stop_scan')
                .done((response) => {
                    if (response.success) {
                        renderScanState(response.data.state);
                        showToast(response.data.message || 'Scan stopped.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to stop the scan.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to stop the scan.', true);
                })
                .always(() => {
                    if (!scanIsRunning) {
                        stopScanButton.disabled = true;
                    }
                });
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

    if (overviewNewScanButton) {
        overviewNewScanButton.addEventListener('click', () => {
            setActiveTab('scanner');

            if (scanIsRunning) {
                return;
            }

            startBackgroundScan(overviewNewScanButton, true);
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

    if (bruteForceForm) {
        bruteForceForm.addEventListener('submit', (event) => {
            event.preventDefault();

            const submitButton = bruteForceForm.querySelector('.firephage-save-bruteforce');
            const formData = new window.FormData(bruteForceForm);
            const settings = {};
            formData.forEach((value, key) => {
                settings[key] = value;
            });

            if (!Object.prototype.hasOwnProperty.call(settings, 'bruteforce_enabled')) {
                settings.bruteforce_enabled = '';
            }

            if (!Object.prototype.hasOwnProperty.call(settings, 'bruteforce_protect_xmlrpc')) {
                settings.bruteforce_protect_xmlrpc = '';
            }

            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = firephageAdmin.labels.savingProtectionSettings;
            }

            request('firephage_save_bruteforce_settings', { settings })
                .done((response) => {
                    if (response.success) {
                        renderBruteForceSummary(response.data.summary);
                        showToast(response.data.message || 'Protection settings saved.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to save protection settings.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to save protection settings.', true);
                })
                .always(() => {
                    if (submitButton) {
                        submitButton.disabled = false;
                        submitButton.textContent = firephageAdmin.labels.saveProtectionSettings;
                    }
                });
        });
    }

    if (clearBruteForceLockoutsButton) {
        clearBruteForceLockoutsButton.addEventListener('click', () => {
            openConfirmModal({
                title: firephageAdmin.labels.confirmClearLockoutsTitle,
                body: firephageAdmin.labels.confirmClearLockoutsBody,
                onConfirm: () => {
                    clearBruteForceLockoutsButton.disabled = true;

                    request('firephage_clear_bruteforce_lockouts')
                        .done((response) => {
                            if (response.success) {
                                renderBruteForceSummary(response.data.summary);
                                showToast(response.data.message || 'Active lockouts cleared.');
                            } else {
                                showToast((response.data && response.data.message) || 'Unable to clear lockouts.', true);
                            }
                        })
                        .fail((xhr) => {
                            showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to clear lockouts.', true);
                        })
                        .always(() => {
                            clearBruteForceLockoutsButton.disabled = false;
                            closeConfirmModal();
                        });
                },
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

                    proTabState.firewallLoaded = false;
                    proTabState.performanceLoaded = false;
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

                    proTabState.firewallLoaded = false;
                    proTabState.performanceLoaded = false;
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

        const tabTargetButton = target.closest('[data-tab-target]');

        if (tabTargetButton instanceof HTMLElement) {
            setActiveTab(tabTargetButton.dataset.tabTarget || 'overview');
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

        if (target.classList.contains('firephage-preview-file')) {
            target.setAttribute('disabled', 'disabled');

            request('firephage_preview_file', {
                file: target.dataset.file || '',
            })
                .done((response) => {
                    if (response.success) {
                        openPreviewModal(response.data.preview);
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to preview the file.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to preview the file.', true);
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

    if (previewModal) {
        previewModal.addEventListener('click', (event) => {
            const target = event.target;

            if (target instanceof HTMLElement && target.dataset.previewClose === '1') {
                closePreviewModal();
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

    if (bruteForceSummaryText) {
        renderBruteForceSummary({
            enabled: bruteForceForm ? !!bruteForceForm.querySelector('input[name="bruteforce_enabled"]')?.checked : false,
            protect_xmlrpc: bruteForceForm ? !!bruteForceForm.querySelector('input[name="bruteforce_protect_xmlrpc"]')?.checked : false,
            threshold: bruteForceForm ? parseInt(bruteForceForm.querySelector('input[name="bruteforce_threshold"]')?.value || '0', 10) : 0,
            window_minutes: bruteForceForm ? parseInt(bruteForceForm.querySelector('input[name="bruteforce_window_minutes"]')?.value || '0', 10) : 0,
            lockout_minutes: bruteForceForm ? parseInt(bruteForceForm.querySelector('input[name="bruteforce_lockout_minutes"]')?.value || '0', 10) : 0,
            active_lockouts_count: bruteForceActiveBadge ? parseInt((bruteForceActiveBadge.textContent || '0').replace(/\D+/g, ''), 10) || 0 : 0,
            status: bruteForceStatusBadge ? bruteForceStatusBadge.className.replace('firephage-badge firephage-badge--', '') : 'neutral',
            summary: bruteForceSummaryText.textContent || '',
        });
    }
}(jQuery));
