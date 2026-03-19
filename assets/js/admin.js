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
    const scannerSettingsForm = document.getElementById('firephage-scanner-settings-form');
    const refreshSignaturesButton = document.querySelector('.firephage-refresh-signatures');
    const notificationSettingsForm = document.getElementById('firephage-notification-settings-form');
    const openScannerSettingsButton = document.querySelector('.firephage-open-scanner-settings');
    const freeTokenModal = document.getElementById('firephage-free-token-modal');
    const freeTokenForm = document.getElementById('firephage-free-token-form');
    const openFreeTokenButtons = Array.from(document.querySelectorAll('.firephage-open-free-token-modal'));
    const declineFreeTokenButton = document.querySelector('.firephage-decline-free-token');
    const dismissFreeTokenButton = document.querySelector('.firephage-dismiss-free-token');
    const checkFreeTokenButtons = Array.from(document.querySelectorAll('.firephage-check-free-token-status'));
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
    const scannerSettingsModal = document.getElementById('firephage-scanner-settings-modal');
    const scannerSettingsFeedback = document.getElementById('firephage-scanner-settings-feedback');
    const signatureLastRefreshed = document.getElementById('firephage-signature-last-refreshed');
    const freeTokenFeedback = document.getElementById('firephage-free-token-feedback');
    const setupWizardModal = document.getElementById('firephage-setup-wizard-modal');
    const setupWizardForm = document.getElementById('firephage-setup-wizard-form');
    const setupWizardFeedback = document.getElementById('firephage-setup-wizard-feedback');
    const applyRecommendedSetupButton = document.querySelector('.firephage-apply-recommended-setup');
    const startQuickScanButton = document.querySelector('.firephage-start-quick-scan');
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
    const firewallPreviewCard = document.getElementById('firephage-firewall-preview-card');
    const performanceStatusBadge = document.getElementById('firephage-performance-status-badge');
    const performanceSummaryText = document.getElementById('firephage-performance-summary-text');
    const performanceConnectionNote = document.getElementById('firephage-performance-connection-note');
    const performanceHostname = document.getElementById('firephage-performance-hostname');
    const performanceImageOptimization = document.getElementById('firephage-performance-image-optimization');
    const performanceEdgeCompression = document.getElementById('firephage-performance-edge-compression');
    const performanceCacheRules = document.getElementById('firephage-performance-cache-rules');
    const performanceUpgradeCard = document.getElementById('firephage-performance-upgrade-card');
    const freeTokenStatusBadge = document.getElementById('firephage-free-token-status-badge');
    const freeTokenSummary = document.getElementById('firephage-free-token-summary');
    const freeTokenSettingsBadge = document.getElementById('firephage-free-token-settings-badge');
    const freeTokenSettingsSummary = document.getElementById('firephage-free-token-settings-summary');
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
    const notificationRecipient = document.getElementById('firephage-notification-recipient');
    const notificationWeekly = document.getElementById('firephage-notification-weekly');
    const notificationMalware = document.getElementById('firephage-notification-malware');
    const notificationLastWeekly = document.getElementById('firephage-notification-last-weekly');
    const notificationAlertSummary = document.getElementById('firephage-notification-alert-summary');
    let pollTimer = null;
    let scanIsRunning = false;
    let currentScanState = {};
    let findingsPage = 1;
    let findingsPageSize = 25;
    let findingsSearchQuery = '';
    let pendingConfirmation = null;
    let selectedFindings = new Set();
    let freeTokenState = firephageAdmin.freeToken || { status: 'pending', email: '', marketingOptIn: false, requiresDecision: true, verificationToken: '' };
    let setupWizardState = firephageAdmin.setupWizard || { shouldOpen: false };
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

    const clearModalFeedback = (feedbackNode) => {
        if (!feedbackNode) {
            return;
        }

        feedbackNode.hidden = true;
        feedbackNode.textContent = '';
        feedbackNode.classList.remove('is-error', 'is-success');
    };

    const showModalFeedback = (feedbackNode, message, isError = false) => {
        if (!feedbackNode) {
            showToast(message, isError);
            return;
        }

        feedbackNode.hidden = false;
        feedbackNode.textContent = message;
        feedbackNode.classList.toggle('is-error', isError);
        feedbackNode.classList.toggle('is-success', !isError);
    };

    const escapeHtml = (value) => String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');

    const humanizeTimestamp = (value) => {
        if (!value) {
            return 'Never';
        }

        const parsed = new Date(String(value).replace(' ', 'T'));

        if (Number.isNaN(parsed.getTime())) {
            return value;
        }

        const delta = Date.now() - parsed.getTime();

        if (delta < 60000) {
            return 'Just now';
        }

        if (delta < 3600000) {
            const minutes = Math.max(1, Math.floor(delta / 60000));
            return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
        }

        if (delta < 86400000) {
            const hours = Math.max(1, Math.floor(delta / 3600000));
            return `${hours} hour${hours === 1 ? '' : 's'} ago`;
        }

        const days = Math.max(1, Math.floor(delta / 86400000));
        return `${days} day${days === 1 ? '' : 's'} ago`;
    };

    const closeConfirmModal = () => {
        pendingConfirmation = null;

        if (!confirmModal || !confirmModalSubmit) {
            return;
        }

        confirmModal.hidden = true;
        confirmModalSubmit.disabled = false;
    };

    const openConfirmModal = ({ title, body, onConfirm, actionLabel = null, danger = true }) => {
        if (!confirmModal || !confirmModalTitle || !confirmModalBody || !confirmModalSubmit) {
            onConfirm();
            return;
        }

        pendingConfirmation = onConfirm;
        confirmModalTitle.textContent = title;
        confirmModalBody.innerHTML = body;
        confirmModalSubmit.textContent = actionLabel || (firephageAdmin.labels.confirmAction || 'Confirm');
        confirmModalSubmit.className = danger ? 'button firephage-button-danger' : 'button button-primary';
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

    const closeScannerSettingsModal = () => {
        if (!scannerSettingsModal) {
            return;
        }

        clearModalFeedback(scannerSettingsFeedback);
        scannerSettingsModal.hidden = true;
    };

    const openScannerSettingsModal = () => {
        if (!scannerSettingsModal) {
            return;
        }

        clearModalFeedback(scannerSettingsFeedback);
        scannerSettingsModal.hidden = false;
    };

    const closeFreeTokenModal = () => {
        if (!freeTokenModal) {
            return;
        }

        clearModalFeedback(freeTokenFeedback);
        freeTokenModal.hidden = true;
    };

    const closeSetupWizardModal = () => {
        if (!setupWizardModal) {
            return;
        }

        clearModalFeedback(setupWizardFeedback);
        setupWizardModal.hidden = true;
    };

    const openFreeTokenModal = () => {
        if (!freeTokenModal) {
            return;
        }

        if (freeTokenForm) {
            const emailInput = freeTokenForm.querySelector('input[name="email"]');
            const marketingInput = freeTokenForm.querySelector('input[name="marketing_opt_in"]');

            if (emailInput && freeTokenState.email && !emailInput.value) {
                emailInput.value = freeTokenState.email;
            }

            if (marketingInput) {
                marketingInput.checked = !!freeTokenState.marketingOptIn;
            }
        }

        clearModalFeedback(freeTokenFeedback);
        freeTokenModal.hidden = false;
    };

    const openSetupWizardModal = () => {
        if (!setupWizardModal) {
            return;
        }

        clearModalFeedback(setupWizardFeedback);
        setupWizardModal.hidden = false;
    };

    const deleteAllSuspiciousFiles = (button) => {
        button.setAttribute('disabled', 'disabled');

        request('firephage_delete_suspicious_files')
            .done((response) => {
                if (response.success) {
                    findingsPage = 1;
                    renderScanState(response.data.state);
                    showToast(response.data.message || 'Malicious files deleted.');
                } else {
                    showToast((response.data && response.data.message) || 'Unable to delete malicious files.', true);
                }
            })
            .fail((xhr) => {
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to delete malicious files.', true);
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
                    showToast(response.data.message || 'The malicious file was deleted.');
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
                    showToast(response.data.message || 'Selected malicious files deleted.');
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

    const renderFreeTokenSummary = (settings = null) => {
        if (settings) {
            freeTokenState = {
                status: settings.free_signature_token_status || 'pending',
                email: settings.free_signature_token_email || '',
                marketingOptIn: settings.free_signature_token_marketing_opt_in === '1',
                requiresDecision: (settings.free_signature_token_status || 'pending') === 'pending',
            };
        }

        let badgeText = 'Pending';
        let badgeTone = 'warning';
        let summaryText = 'Choose whether you want a free FirePhage token for fresher malware-signature updates.';

        if (freeTokenState.status === 'registered') {
            badgeText = 'Active';
            badgeTone = 'good';
            summaryText = freeTokenState.email
                ? `Signature updates are active with the free FirePhage token sent to ${freeTokenState.email}.`
                : 'Signature updates are active with your free FirePhage token.';
        } else if (freeTokenState.status === 'awaiting_verification') {
            badgeText = 'Verify Email';
            badgeTone = 'warning';
            summaryText = 'Verification email sent. Open your inbox, click the FirePhage verification link, then return here and check verification status to activate remote signature updates.';
        } else if (freeTokenState.status === 'declined') {
            badgeText = 'Declined';
            badgeTone = 'neutral';
            summaryText = 'Remote FirePhage signature updates are turned off. You can request a free token later at any time.';
        } else if (freeTokenState.status === 'dismissed') {
            badgeText = 'Hidden';
            badgeTone = 'neutral';
            summaryText = 'The free-token prompt is hidden. You can still request a free token later from the plugin whenever you want fresher FirePhage signature updates.';
        }

        setBadge(freeTokenStatusBadge, badgeText, badgeTone);
        setBadge(freeTokenSettingsBadge, badgeText, badgeTone);

        if (freeTokenSummary) {
            freeTokenSummary.textContent = summaryText;
        }

        if (freeTokenSettingsSummary) {
            freeTokenSettingsSummary.textContent = summaryText;
        }

        checkFreeTokenButtons.forEach((button) => {
            button.style.display = freeTokenState.status === 'awaiting_verification' ? '' : 'none';
        });
    };

    const renderFirewallSummary = (payload) => {
        if (!firewallSummaryText || !firewallConnectionNote) {
            return;
        }

        if (!payload.connected) {
            setBadge(firewallStatusBadge, 'Connect', 'neutral');
            firewallSummaryText.textContent = 'Connect to view live firewall analytics.';
            firewallConnectionNote.textContent = payload.message || 'Connect FirePhage to load live traffic filtering and edge analytics for this site.';
            if (firewallPreviewCard) {
                firewallPreviewCard.style.display = '';
            }
            return;
        }

        const statusTone = payload.pro_enabled ? 'good' : 'warning';
        setBadge(firewallStatusBadge, payload.pro_enabled ? 'Live' : 'Plan Required', statusTone);
        firewallSummaryText.textContent = `${payload.status.label} on ${payload.site.domain}. WAF status: ${payload.status.waf_status}.`;
        firewallConnectionNote.textContent = payload.pro_enabled ? 'Live firewall telemetry is loaded from your connected FirePhage site.' : (payload.message || firephageAdmin.labels.proInactive);

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
                : '<div class="firephage-pro-table__row"><span>No recent events</span><span>Live firewall analytics will appear here after traffic is processed.</span><span>/</span></div>';
        }

        if (firewallUpgradeCard) {
            firewallUpgradeCard.style.display = payload.pro_enabled ? 'none' : '';
        }

        if (firewallPreviewCard) {
            firewallPreviewCard.style.display = payload.pro_enabled ? 'none' : '';
        }
    };

    const renderPerformanceSummary = (payload) => {
        if (!performanceSummaryText || !performanceConnectionNote) {
            return;
        }

        if (!payload.connected) {
            setBadge(performanceStatusBadge, 'Connect', 'neutral');
            performanceSummaryText.textContent = 'Connect to load performance data.';
            performanceConnectionNote.textContent = payload.message || 'Upgrade required to manage CDN and cache settings from WordPress.';
            return;
        }

        const tone = payload.pro_enabled ? 'good' : 'warning';
        setBadge(performanceStatusBadge, payload.pro_enabled ? 'Live' : 'Plan Required', tone);
        performanceSummaryText.textContent = `${payload.summary.requests_24h || 0} requests over the last 24 hours. Cache hit ratio: ${payload.summary.cache_hit_ratio || 0}%.`;
        performanceConnectionNote.textContent = payload.pro_enabled ? 'Live CDN and cache telemetry is loaded from your connected FirePhage site.' : (payload.message || firephageAdmin.labels.proInactive);

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
                : '<div class="firephage-pro-table__row"><span>No live rules yet</span><span>Connect FirePhage to review managed cache behavior.</span><span>Waiting</span></div>';
        }

        if (performanceUpgradeCard) {
            performanceUpgradeCard.style.display = payload.pro_enabled ? 'none' : '';
        }
    };

    const bruteForceRowsMarkup = (rows, showRemaining = false) => {
        if (!rows || rows.length === 0) {
            return `<p class="firephage-empty">${showRemaining ? 'No active lockouts right now.' : 'No recent lockout events right now.'}</p>`;
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

    const renderNotificationSummary = (settings, state = null) => {
        if (!settings) {
            return;
        }

        if (notificationRecipient) {
            notificationRecipient.textContent = settings.notification_email || 'Admin email';
        }

        if (notificationWeekly) {
            notificationWeekly.textContent = settings.notifications_weekly_report === '1' ? 'On' : 'Off';
        }

        if (notificationMalware) {
            notificationMalware.textContent = settings.notifications_alert_malware === '1' ? 'On' : 'Off';
        }

        if (notificationLastWeekly && state) {
            notificationLastWeekly.textContent = state.last_weekly_report_at || 'Not sent yet';
        }

        if (notificationAlertSummary && state) {
            notificationAlertSummary.innerHTML = `
                <div class="firephage-pro-table__row"><span>Malware</span><span>${state.last_malware_alert_scan_id || 'No alert yet'}</span><span>${settings.notifications_alert_malware === '1' ? 'Enabled' : 'Disabled'}</span></div>
                <div class="firephage-pro-table__row"><span>Core edits</span><span>${state.last_core_alert_scan_id || 'No alert yet'}</span><span>${settings.notifications_alert_core_edits === '1' ? 'Enabled' : 'Disabled'}</span></div>
            `;
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

    const statusLabel = (status) => {
        if (status === 'completed') {
            return 'Completed';
        }

        if (status === 'failed') {
            return 'Needs Review';
        }

        if (status === 'discovering') {
            return 'Preparing Scan';
        }

        if (status === 'scanning') {
            return 'Scanning';
        }

        if (status === 'stopped') {
            return 'Cancelled';
        }

        return 'Idle';
    };

    const progressLabel = (state) => {
        const scanModeLabel = state.scan_mode === 'quick' ? 'Quick Scan' : 'Deep Scan';

        if (state.status === 'idle') {
            return 'The scanner is idle. Start a background scan to verify repository integrity and review untrusted code paths.';
        }

        if (state.status === 'discovering') {
            return `${scanModeLabel}: discovering candidate files: ${state.discovered_files} found so far.`;
        }

        if (state.status === 'stopped') {
            return `${scanModeLabel} cancelled at ${state.scanned_files} of ${state.discovered_files} discovered files. Trusted: ${state.trusted_files}. Clean custom files: ${state.clean_files || 0}. Skipped: ${state.skipped_files || 0}. Integrity mismatches: ${state.integrity_issues}. Malicious: ${state.suspicious_files}. Use Resume Scan to continue from the saved position.`;
        }

        if (state.status === 'completed') {
            return `${scanModeLabel} completed. ${state.scanned_files} files scanned, ${state.trusted_files} trusted, ${state.clean_files || 0} clean custom files, ${state.skipped_files || 0} skipped, ${state.integrity_issues} integrity mismatches, ${state.suspicious_files} malicious.`;
        }

        if (state.status === 'failed') {
            return `Scan failed: ${state.last_error || 'Unknown error'}`;
        }

        return `${scanModeLabel}: scanning ${state.scanned_files} of ${state.discovered_files} discovered files. Trusted: ${state.trusted_files}. Clean custom files: ${state.clean_files || 0}. Skipped: ${state.skipped_files || 0}. Integrity mismatches: ${state.integrity_issues}. Malicious: ${state.suspicious_files}. Current file: ${state.current_file || 'Waiting...'}`;
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

    const findingsSearchText = (finding) => {
        if (!finding || typeof finding !== 'object') {
            return '';
        }

        const parts = [
            finding.file || '',
            finding.type || '',
            finding.source || '',
            finding.confidence || '',
        ];

        if (finding.reasons && Array.isArray(finding.reasons)) {
            parts.push(finding.reasons.join(' '));
        }

        return parts.join(' ').toLowerCase();
    };

    const findingsMarkup = (findings) => {
        if (!findings || findings.length === 0) {
            selectedFindings = new Set();
            return '<p class="firephage-empty">No malicious files detected in the latest scan.</p>';
        }

        const searchQuery = findingsSearchQuery.trim().toLowerCase();
        const rows = findings.slice().reverse().filter((finding) => {
            if (searchQuery === '') {
                return true;
            }

            return findingsSearchText(finding).includes(searchQuery);
        });

        if (rows.length === 0) {
            return `<div class="firephage-findings-toolbar">
                <label class="firephage-findings-search">
                    <span class="screen-reader-text">${escapeHtml(firephageAdmin.labels.findingsSearchLabel || 'Search findings')}</span>
                    <input type="search" class="firephage-findings-search-input" placeholder="${escapeHtml(firephageAdmin.labels.findingsSearchPlaceholder || 'Search findings...')}" value="${escapeHtml(findingsSearchQuery)}" />
                </label>
                <div class="firephage-findings-actions">
                    <button type="button" class="button button-secondary firephage-clear-findings">${firephageAdmin.labels.clearFindings}</button>
                </div>
            </div>
            <p class="firephage-empty">No findings match the current search.</p>`;
        }

        const availablePageSizes = pageSizeOptions(rows.length);
        if (!availablePageSizes.includes(findingsPageSize)) {
            findingsPageSize = availablePageSizes.includes(25) ? 25 : availablePageSizes[availablePageSizes.length - 1];
        }
        const totalPages = Math.max(1, Math.ceil(rows.length / findingsPageSize));
        findingsPage = Math.min(findingsPage, totalPages);
        const start = (findingsPage - 1) * findingsPageSize;
        const pagedRows = rows.slice(start, start + findingsPageSize);

        return `<div class="firephage-findings-toolbar">
            <label class="firephage-findings-search">
                <span class="screen-reader-text">${escapeHtml(firephageAdmin.labels.findingsSearchLabel || 'Search findings')}</span>
                <input type="search" class="firephage-findings-search-input" placeholder="${escapeHtml(firephageAdmin.labels.findingsSearchPlaceholder || 'Search findings...')}" value="${escapeHtml(findingsSearchQuery)}" />
            </label>
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
                        const status = finding.type === 'malware' ? 'Malicious' : 'Integrity mismatch';
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
            badge.textContent = statusLabel(state.status);
        }

        if (overviewBadge) {
            overviewBadge.className = `firephage-badge ${badgeClass(state.status)}`;
            overviewBadge.textContent = statusLabel(state.status);
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

        const scannerLastScan = document.getElementById('firephage-scanner-last-scan');
        const overviewLastScan = document.getElementById('firephage-overview-last-scan');

        if (scannerLastScan) {
            scannerLastScan.textContent = humanizeTimestamp(state.finished_at || '');
        }

        if (overviewLastScan) {
            overviewLastScan.textContent = humanizeTimestamp(state.finished_at || '');
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
                : (state.status === 'stopped' ? firephageAdmin.labels.resumeScan : (firephageAdmin.labels.startDeepScan || firephageAdmin.labels.startScan));
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

        if (startQuickScanButton) {
            startQuickScanButton.style.display = scanIsRunning ? 'none' : '';
            startQuickScanButton.disabled = scanIsRunning;
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

    const startBackgroundScan = (button = null, forceNew = false, scanMode = 'deep') => {
        const resumingScan = currentScanState.status === 'stopped';
        const startingFresh = forceNew;
        const effectiveMode = resumingScan && !startingFresh ? (currentScanState.scan_mode || 'deep') : scanMode;
        const startingLabel = effectiveMode === 'quick'
            ? (firephageAdmin.labels.scanStartingQuick || 'Starting Quick Scan…')
            : (firephageAdmin.labels.scanStartingDeep || firephageAdmin.labels.scanStarting);

        if (button) {
            button.disabled = true;
            button.textContent = (resumingScan && !startingFresh) ? firephageAdmin.labels.scanResuming : startingLabel;
        }

        if (startScanButton) {
            startScanButton.disabled = true;
            startScanButton.textContent = (resumingScan && !startingFresh) ? firephageAdmin.labels.scanResuming : startingLabel;
        }

        if (startNewScanButton) {
            startNewScanButton.disabled = true;
        }

        if (startQuickScanButton) {
            startQuickScanButton.disabled = true;
        }

        if (overviewNewScanButton) {
            overviewNewScanButton.disabled = true;
        }

        request('firephage_start_scan', {
            force_new: forceNew ? '1' : '',
            scan_mode: effectiveMode,
        })
            .done((response) => {
                if (response.success) {
                    renderScanState(response.data.state);
                    showToast(startingFresh
                        ? (effectiveMode === 'quick' ? 'A new Quick Scan started.' : 'A new Deep Scan started.')
                        : (resumingScan ? 'Background malware scan resumed.' : (effectiveMode === 'quick' ? 'Quick Scan started.' : 'Deep Scan started.')));
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
                        startScanButton.textContent = currentScanState.status === 'stopped' ? firephageAdmin.labels.resumeScan : (firephageAdmin.labels.startDeepScan || firephageAdmin.labels.startScan);
                    }

                    if (button) {
                        button.disabled = false;
                        button.textContent = currentScanState.status === 'stopped' ? firephageAdmin.labels.overviewResumeScan : (effectiveMode === 'quick' ? (firephageAdmin.labels.startQuickScan || 'Start Quick Scan') : (firephageAdmin.labels.startDeepScan || firephageAdmin.labels.overviewStartScan));
                    }

                    if (startNewScanButton) {
                        startNewScanButton.disabled = false;
                    }

                    if (startQuickScanButton) {
                        startQuickScanButton.disabled = false;
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

    if (startQuickScanButton) {
        startQuickScanButton.addEventListener('click', () => {
            openConfirmModal({
                title: firephageAdmin.labels.quickScanTitle || 'Start Quick Scan?',
                body: `<p>${escapeHtml(firephageAdmin.labels.quickScanBody || 'Quick Scan is faster, but it is less effective than Deep Scan.')}</p>`,
                actionLabel: firephageAdmin.labels.quickScanAction || 'Start Quick Scan',
                danger: false,
                onConfirm: () => startBackgroundScan(startQuickScanButton, true, 'quick'),
            });
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
                        showToast(firephageAdmin.labels.refreshHealthDone || 'Health checks refreshed.');
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

    if (scannerSettingsForm) {
        scannerSettingsForm.addEventListener('submit', (event) => {
            event.preventDefault();
            clearModalFeedback(scannerSettingsFeedback);

            const submitButton = scannerSettingsForm.querySelector('.firephage-save-scanner-settings');
            const formData = new window.FormData(scannerSettingsForm);
            const settings = {};
            formData.forEach((value, key) => {
                settings[key] = value;
            });

            if (!Object.prototype.hasOwnProperty.call(settings, 'malware_auto_scans_enabled')) {
                settings.malware_auto_scans_enabled = '';
            }

            if (!Object.prototype.hasOwnProperty.call(settings, 'use_firephage_signature_feed')) {
                settings.use_firephage_signature_feed = '';
            }

            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = firephageAdmin.labels.savingScannerSettings;
            }

            request('firephage_save_scanner_settings', { settings })
                .done((response) => {
                    if (response.success) {
                        const autoScanNode = document.getElementById('firephage-scanner-auto-scan');
                        if (autoScanNode && response.data.settings) {
                            autoScanNode.textContent = response.data.settings.malware_auto_scans_enabled === '1' ? 'Enabled' : 'Disabled';
                        }
                        showModalFeedback(scannerSettingsFeedback, response.data.message || 'Scanner settings saved.');
                    } else {
                        showModalFeedback(scannerSettingsFeedback, (response.data && response.data.message) || 'Unable to save scanner settings.', true);
                    }
                })
                .fail((xhr) => {
                    showModalFeedback(scannerSettingsFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to save scanner settings.', true);
                })
                .always(() => {
                    if (submitButton) {
                        submitButton.disabled = false;
                        submitButton.textContent = firephageAdmin.labels.saveScannerSettings;
                    }
                });
        });
    }

    if (refreshSignaturesButton) {
        refreshSignaturesButton.addEventListener('click', () => {
            clearModalFeedback(scannerSettingsFeedback);
            refreshSignaturesButton.disabled = true;
            refreshSignaturesButton.textContent = firephageAdmin.labels.refreshingSignatures || 'Refreshing signatures...';

            request('firephage_refresh_signatures')
                .done((response) => {
                    if (response.success) {
                        if (signatureLastRefreshed && response.data && response.data.last_refreshed_label) {
                            signatureLastRefreshed.textContent = response.data.last_refreshed_label;
                        }
                        showModalFeedback(scannerSettingsFeedback, (response.data && response.data.message) || firephageAdmin.labels.refreshSignaturesDone || 'FirePhage signatures refreshed.');
                    } else {
                        showModalFeedback(scannerSettingsFeedback, (response.data && response.data.message) || 'Unable to refresh signatures.', true);
                    }
                })
                .fail((xhr) => {
                    showModalFeedback(scannerSettingsFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to refresh signatures.', true);
                })
                .always(() => {
                    refreshSignaturesButton.disabled = false;
                    refreshSignaturesButton.textContent = firephageAdmin.labels.refreshSignatures || 'Refresh Signatures';
                });
        });
    }

    if (notificationSettingsForm) {
        notificationSettingsForm.addEventListener('submit', (event) => {
            event.preventDefault();

            const submitButton = notificationSettingsForm.querySelector('.firephage-save-notification-settings');
            const formData = new window.FormData(notificationSettingsForm);
            const settings = {};
            formData.forEach((value, key) => {
                settings[key] = value;
            });

            ['notifications_enabled', 'notifications_weekly_report', 'notifications_alert_malware', 'notifications_alert_core_edits'].forEach((key) => {
                if (!Object.prototype.hasOwnProperty.call(settings, key)) {
                    settings[key] = '';
                }
            });

            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = firephageAdmin.labels.savingNotificationSettings;
            }

            request('firephage_save_notification_settings', { settings })
                .done((response) => {
                    if (response.success) {
                        renderNotificationSummary(response.data.settings, response.data.state);
                        showToast(response.data.message || 'Notification settings saved.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to save notification settings.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to save notification settings.', true);
                })
                .always(() => {
                    if (submitButton) {
                        submitButton.disabled = false;
                        submitButton.textContent = firephageAdmin.labels.saveNotificationSettings;
                    }
                });
        });
    }

    const completeSetupWizard = (mode = 'custom') => {
        if (!setupWizardForm) {
            return;
        }

        clearModalFeedback(setupWizardFeedback);

        const submitButton = setupWizardForm.querySelector('.firephage-save-setup-wizard');
        const frequencySelect = setupWizardForm.querySelector('select[name="malware_auto_scan_interval"]');
        const profileSelect = setupWizardForm.querySelector('select[name="bruteforce_profile"]');

        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = mode === 'recommended'
                ? (firephageAdmin.labels.applyRecommendedSetup || 'Applying recommended settings...')
                : (firephageAdmin.labels.saveSetupWizard || 'Saving setup and starting your first scan...');
        }

        if (applyRecommendedSetupButton) {
            applyRecommendedSetupButton.disabled = true;
        }

        request('firephage_complete_setup_wizard', {
            mode,
            malware_auto_scan_interval: frequencySelect ? frequencySelect.value : 'twice_daily',
            bruteforce_profile: profileSelect ? profileSelect.value : 'recommended',
        })
            .done((response) => {
                if (response.success) {
                    setupWizardState.shouldOpen = false;

                    if (scannerSettingsForm && response.data.settings) {
                        const autoScanToggle = scannerSettingsForm.querySelector('input[name="malware_auto_scans_enabled"]');
                        const scanInterval = scannerSettingsForm.querySelector('select[name="malware_auto_scan_interval"]');
                        const scannerAutoScanStatus = document.getElementById('firephage-scanner-auto-scan');

                        if (autoScanToggle) {
                            autoScanToggle.checked = response.data.settings.malware_auto_scans_enabled === '1';
                        }

                        if (scanInterval) {
                            scanInterval.value = response.data.settings.malware_auto_scan_interval || 'twice_daily';
                        }

                         if (scannerAutoScanStatus) {
                            scannerAutoScanStatus.textContent = response.data.settings.malware_auto_scans_enabled === '1' ? 'Enabled' : 'Disabled';
                        }
                    }

                    if (bruteForceForm && response.data.settings) {
                        const enabledToggle = bruteForceForm.querySelector('input[name="bruteforce_enabled"]');
                        const xmlrpcToggle = bruteForceForm.querySelector('input[name="bruteforce_protect_xmlrpc"]');
                        const thresholdInput = bruteForceForm.querySelector('input[name="bruteforce_threshold"]');
                        const windowInput = bruteForceForm.querySelector('input[name="bruteforce_window_minutes"]');
                        const lockoutInput = bruteForceForm.querySelector('input[name="bruteforce_lockout_minutes"]');

                        if (enabledToggle) {
                            enabledToggle.checked = response.data.settings.bruteforce_enabled === '1';
                        }

                        if (xmlrpcToggle) {
                            xmlrpcToggle.checked = response.data.settings.bruteforce_protect_xmlrpc === '1';
                        }

                        if (thresholdInput) {
                            thresholdInput.value = response.data.settings.bruteforce_threshold || thresholdInput.value;
                        }

                        if (windowInput) {
                            windowInput.value = response.data.settings.bruteforce_window_minutes || windowInput.value;
                        }

                        if (lockoutInput) {
                            lockoutInput.value = response.data.settings.bruteforce_lockout_minutes || lockoutInput.value;
                        }
                    }

                    if (response.data.bruteforce_summary) {
                        renderBruteForceSummary(response.data.bruteforce_summary);
                    }

                    if (response.data.scan_state) {
                        renderScanState(response.data.scan_state);
                    }

                    closeSetupWizardModal();
                    setActiveTab('scanner');
                    showToast(response.data.message || 'Setup saved. Your first scan has started.');
                } else {
                    showModalFeedback(setupWizardFeedback, (response.data && response.data.message) || 'Unable to save setup right now.', true);
                }
            })
            .fail((xhr) => {
                showModalFeedback(setupWizardFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to save setup right now.', true);
            })
            .always(() => {
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.textContent = 'Save and Start First Scan';
                }

                if (applyRecommendedSetupButton) {
                    applyRecommendedSetupButton.disabled = false;
                }
            });
    };

    if (setupWizardForm) {
        setupWizardForm.addEventListener('submit', (event) => {
            event.preventDefault();
            completeSetupWizard('custom');
        });
    }

    if (applyRecommendedSetupButton && setupWizardForm) {
        applyRecommendedSetupButton.addEventListener('click', () => {
            const frequencySelect = setupWizardForm.querySelector('select[name="malware_auto_scan_interval"]');
            const profileSelect = setupWizardForm.querySelector('select[name="bruteforce_profile"]');

            if (frequencySelect) {
                frequencySelect.value = 'twice_daily';
            }

            if (profileSelect) {
                profileSelect.value = 'recommended';
            }

            completeSetupWizard('recommended');
        });
    }

    if (openScannerSettingsButton) {
        openScannerSettingsButton.addEventListener('click', () => {
            openScannerSettingsModal();
        });
    }

    openFreeTokenButtons.forEach((button) => {
        button.addEventListener('click', () => {
            openFreeTokenModal();
        });
    });

    if (freeTokenForm) {
        freeTokenForm.addEventListener('submit', (event) => {
            event.preventDefault();
            clearModalFeedback(freeTokenFeedback);

            const submitButton = freeTokenForm.querySelector('.firephage-register-free-token');
            const emailInput = freeTokenForm.querySelector('input[name="email"]');
            const marketingInput = freeTokenForm.querySelector('input[name="marketing_opt_in"]');

            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = firephageAdmin.labels.registeringFreeToken;
            }

            request('firephage_register_free_token', {
                email: emailInput ? emailInput.value : '',
                marketing_opt_in: marketingInput && marketingInput.checked ? '1' : '',
            })
                .done((response) => {
                    if (response.success) {
                        renderFreeTokenSummary(response.data.settings || null);
                        showModalFeedback(freeTokenFeedback, response.data.message || 'Free token activated.');
                    } else {
                        showModalFeedback(freeTokenFeedback, (response.data && response.data.message) || 'Unable to register the free token.', true);
                    }
                })
                .fail((xhr) => {
                    showModalFeedback(freeTokenFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to register the free token.', true);
                })
                .always(() => {
                    if (submitButton) {
                        submitButton.disabled = false;
                        submitButton.textContent = firephageAdmin.labels.registerFreeToken;
                    }
                });
        });
    }

    if (declineFreeTokenButton) {
        declineFreeTokenButton.addEventListener('click', () => {
            clearModalFeedback(freeTokenFeedback);
            declineFreeTokenButton.disabled = true;

            request('firephage_decline_free_token')
                .done((response) => {
                    if (response.success) {
                        renderFreeTokenSummary(response.data.settings || null);
                        showModalFeedback(freeTokenFeedback, response.data.message || 'Free token declined.');
                    } else {
                        showModalFeedback(freeTokenFeedback, (response.data && response.data.message) || 'Unable to save your choice.', true);
                    }
                })
                .fail((xhr) => {
                    showModalFeedback(freeTokenFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to save your choice.', true);
                })
                .always(() => {
                    declineFreeTokenButton.disabled = false;
                });
        });
    }

    if (dismissFreeTokenButton) {
        dismissFreeTokenButton.addEventListener('click', () => {
            clearModalFeedback(freeTokenFeedback);
            dismissFreeTokenButton.disabled = true;

            request('firephage_dismiss_free_token_prompt')
                .done((response) => {
                    if (response.success) {
                        renderFreeTokenSummary(response.data.settings || null);
                        showModalFeedback(freeTokenFeedback, response.data.message || 'Prompt hidden.');
                    } else {
                        showModalFeedback(freeTokenFeedback, (response.data && response.data.message) || 'Unable to save your choice.', true);
                    }
                })
                .fail((xhr) => {
                    showModalFeedback(freeTokenFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to save your choice.', true);
                })
                .always(() => {
                    dismissFreeTokenButton.disabled = false;
                });
        });
    }

    checkFreeTokenButtons.forEach((button) => {
        button.addEventListener('click', () => {
            clearModalFeedback(freeTokenFeedback);
            button.disabled = true;
            button.textContent = firephageAdmin.labels.checkingFreeTokenStatus;

            request('firephage_check_free_token_status')
                .done((response) => {
                    if (response.success) {
                        renderFreeTokenSummary(response.data.settings || null);
                        showModalFeedback(freeTokenFeedback, response.data.message || 'Verification status updated.');
                    } else {
                        showModalFeedback(freeTokenFeedback, (response.data && response.data.message) || 'Unable to check verification status.', true);
                    }
                })
                .fail((xhr) => {
                    showModalFeedback(freeTokenFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to check verification status.', true);
                })
                .always(() => {
                    checkFreeTokenButtons.forEach((node) => {
                        node.disabled = false;
                        node.textContent = firephageAdmin.labels.checkFreeTokenStatus;
                    });
                });
        });
    });

    if (freeTokenState.verificationToken) {
        request('firephage_verify_free_token', {
            verification_token: freeTokenState.verificationToken,
        })
            .done((response) => {
                if (response.success) {
                    renderFreeTokenSummary(response.data.settings || null);
                    showToast(response.data.message || 'Email verified.');
                } else {
                    showToast((response.data && response.data.message) || 'Unable to verify the email link.', true);
                }
            })
            .fail((xhr) => {
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to verify the email link.', true);
            })
            .always(() => {
                if (window.history && typeof window.history.replaceState === 'function') {
                    const url = new URL(window.location.href);
                    url.searchParams.delete('firephage_verify');
                    window.history.replaceState({}, document.title, url.toString());
                }
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

    app.addEventListener('input', (event) => {
        if (!(event.target instanceof HTMLInputElement) || !event.target.classList.contains('firephage-findings-search-input')) {
            return;
        }

        findingsSearchQuery = event.target.value || '';
        findingsPage = 1;
        rerenderFindings();
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
                        openPreviewModal(response.data.preview || response.data);
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
            const malwareFiles = (currentScanState.findings || []).filter((finding) => finding.type === 'malware').map((finding) => finding.file);
            openConfirmModal({
                title: firephageAdmin.labels.confirmDeleteAllTitle,
                body: `<p>${escapeHtml(firephageAdmin.labels.confirmDeleteAllBody)}</p><p><strong>${escapeHtml(firephageAdmin.labels.deleteModalWarning)}</strong></p><p>${escapeHtml(firephageAdmin.labels.deleteModalBackup)}</p><p><strong>${escapeHtml(firephageAdmin.labels.deleteModalCountLabel || 'Files marked as malicious')}:</strong> ${malwareFiles.length}</p>`,
                onConfirm: () => deleteAllSuspiciousFiles(target),
            });
            return;
        }

        if (target.classList.contains('firephage-delete-selected-suspicious-files')) {
            const files = Array.from(selectedFindings);
            openConfirmModal({
                title: firephageAdmin.labels.confirmDeleteSelectedTitle,
                body: `<p>${escapeHtml(firephageAdmin.labels.confirmDeleteSelectedBody)}</p><p><strong>${escapeHtml(firephageAdmin.labels.deleteModalWarning)}</strong></p><p>${escapeHtml(firephageAdmin.labels.deleteModalBackup)}</p><p><strong>${escapeHtml(firephageAdmin.labels.deleteModalFilesLabel)}:</strong></p><div class="firephage-confirm-files">${files.slice(0, 8).map((file) => `<code>${escapeHtml(file)}</code>`).join('')}</div>`,
                onConfirm: () => deleteSelectedSuspiciousFiles(target),
            });
            return;
        }

        if (target.classList.contains('firephage-delete-finding')) {
            const filePath = target.dataset.file || '';
            openConfirmModal({
                title: firephageAdmin.labels.confirmDeleteTitle,
                body: `<p>${escapeHtml(firephageAdmin.labels.confirmDeleteBody)}</p><p><strong>${escapeHtml(firephageAdmin.labels.deleteModalWarning)}</strong></p><p>${escapeHtml(firephageAdmin.labels.deleteModalBackup)}</p><p><strong>${escapeHtml(firephageAdmin.labels.deleteModalFileLabel)}:</strong></p><div class="firephage-confirm-files"><code>${escapeHtml(filePath)}</code></div>`,
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

    if (scannerSettingsModal) {
        scannerSettingsModal.addEventListener('click', (event) => {
            const target = event.target;

            if (target instanceof HTMLElement && target.dataset.scannerSettingsClose === '1') {
                closeScannerSettingsModal();
            }
        });
    }

    if (freeTokenModal) {
        freeTokenModal.addEventListener('click', (event) => {
            const target = event.target;

            if (target instanceof HTMLElement && target.dataset.freeTokenClose === '1') {
                closeFreeTokenModal();
            }
        });
    }

    if (setupWizardModal) {
        setupWizardModal.addEventListener('click', (event) => {
            const target = event.target;

            if (target instanceof HTMLElement && target.dataset.setupWizardClose === '1') {
                closeSetupWizardModal();
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

    if (notificationSettingsForm) {
        renderNotificationSummary({
            notification_email: notificationSettingsForm.querySelector('input[name="notification_email"]')?.value || '',
            notifications_weekly_report: notificationSettingsForm.querySelector('input[name="notifications_weekly_report"]')?.checked ? '1' : '0',
            notifications_alert_malware: notificationSettingsForm.querySelector('input[name="notifications_alert_malware"]')?.checked ? '1' : '0',
            notifications_alert_core_edits: notificationSettingsForm.querySelector('input[name="notifications_alert_core_edits"]')?.checked ? '1' : '0',
        });
    }

    renderFreeTokenSummary();

    if (setupWizardState.shouldOpen) {
        openSetupWizardModal();
    } else if (freeTokenState.requiresDecision) {
        openFreeTokenModal();
    }
}(jQuery));
