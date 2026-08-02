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
    const setupWizardNextButton = document.querySelector('.firephage-setup-wizard-next');
    const setupWizardBackButton = document.querySelector('.firephage-setup-wizard-back');
    const applyRecommendedSetupButton = document.querySelector('.firephage-apply-recommended-setup');
    const startQuickScanButton = document.querySelector('.firephage-start-quick-scan');
    const firewallStatusBadge = document.getElementById('firephage-firewall-status-badge');
    const firewallSummaryText = document.getElementById('firephage-firewall-summary-text');
    const firewallConnectionNote = document.getElementById('firephage-firewall-connection-note');
    const firewallTotalRequests = document.getElementById('firephage-firewall-total-requests');
    const firewallRequestsBlocked = document.getElementById('firephage-firewall-requests-blocked');
    const firewallChallengeRate = document.getElementById('firephage-firewall-challenge-rate');
    const firewallBotPressure = document.getElementById('firephage-firewall-bot-pressure');
    const firewallActivityBody = document.getElementById('firephage-firewall-activity-body');
    const firewallActivityBadge = document.getElementById('firephage-firewall-activity-badge');
    const firewallRangeSelect = document.getElementById('firephage-firewall-range');
    const firewallProtectionMode = document.getElementById('firephage-firewall-protection-mode');
    const firewallBlockIpInput = document.getElementById('firephage-firewall-block-ip');
    const firewallBlockIpButton = document.getElementById('firephage-firewall-block-ip-button');
    const firewallAllowIpInput = document.getElementById('firephage-firewall-allow-ip');
    const firewallAllowIpButton = document.getElementById('firephage-firewall-allow-ip-button');
    const firewallBlockCountrySelect = document.getElementById('firephage-firewall-block-country');
    const firewallBlockCountryButton = document.getElementById('firephage-firewall-block-country-button');
    const firewallBlockContinentSelect = document.getElementById('firephage-firewall-block-continent');
    const firewallBlockContinentButton = document.getElementById('firephage-firewall-block-continent-button');
    let firewallCountryChoices = null;
    let firewallContinentChoices = null;
    let firewallCountryOptionMap = {};
    let firewallContinentOptionMap = {};
    const firewallRuleTabButtons = Array.from(document.querySelectorAll('[data-firewall-rule-tab]'));
    const firewallRulePanels = Array.from(document.querySelectorAll('[data-firewall-rule-panel]'));
    const firewallIpRulesList = document.getElementById('firephage-firewall-rules-ip');
    const firewallCountryRulesList = document.getElementById('firephage-firewall-rules-country');
    const firewallContinentRulesList = document.getElementById('firephage-firewall-rules-continent');
    const firewallControlsBadge = document.getElementById('firephage-firewall-controls-badge');
    const firewallControlsNote = document.getElementById('firephage-firewall-controls-note');
    const firewallUpgradeCard = document.getElementById('firephage-firewall-upgrade-card');
    const firewallPreviewCard = document.getElementById('firephage-firewall-preview-card');
    const firewallInsightsBadge = document.getElementById('firephage-firewall-insights-badge');
    const firewallInsightsSummary = document.getElementById('firephage-firewall-insights-summary');
    const firewallCountriesPanel = document.getElementById('firephage-firewall-countries-panel');
    const firewallIpsPanel = document.getElementById('firephage-firewall-ips-panel');
    const firewallInsightsNote = document.getElementById('firephage-firewall-insights-note');
    const performanceStatusBadge = document.getElementById('firephage-performance-status-badge');
    const performanceSummaryText = document.getElementById('firephage-performance-summary-text');
    const performanceConnectionNote = document.getElementById('firephage-performance-connection-note');
    const performanceRouting = document.getElementById('firephage-performance-routing');
    const performanceTroubleshooting = document.getElementById('firephage-performance-troubleshooting');
    const performanceImageOptimization = document.getElementById('firephage-performance-image-optimization');
    const performanceEdgeCompression = document.getElementById('firephage-performance-edge-compression');
    const performanceCacheRules = document.getElementById('firephage-performance-cache-rules');
    const performanceUpgradeCard = document.getElementById('firephage-performance-upgrade-card');
    const performancePurgeCacheButton = document.getElementById('firephage-performance-purge-cache');
    const performanceToggleTroubleshootingButton = document.getElementById('firephage-performance-toggle-troubleshooting');
    const freeTokenStatusBadge = document.getElementById('firephage-free-token-status-badge');
    const freeTokenSummary = document.getElementById('firephage-free-token-summary');
    const freeTokenSettingsBadge = document.getElementById('firephage-free-token-settings-badge');
    const freeTokenSettingsSummary = document.getElementById('firephage-free-token-settings-summary');
    const bruteForceOverviewBadge = document.getElementById('firephage-bruteforce-overview-badge');
    const bruteForceOverviewSummary = document.getElementById('firephage-bruteforce-overview-summary');
    const bruteForceStatusBadge = document.getElementById('firephage-bruteforce-status-badge');
    const bruteForceSnapshotBadge = document.getElementById('firephage-bruteforce-snapshot-badge');
    const bruteForceSummaryText = document.getElementById('firephage-bruteforce-summary-text');
    const bruteForceLocalPanel = document.getElementById('firephage-bruteforce-local-panel');
    const bruteForceManagedPanel = document.getElementById('firephage-bruteforce-managed-panel');
    const bruteForceLocalHistory = document.getElementById('firephage-bruteforce-local-history');
    const bruteForceManagedHistory = document.getElementById('firephage-bruteforce-managed-history');
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
    const notificationProBadge = document.getElementById('firephage-notification-pro-badge');
    const notificationProNote = document.getElementById('firephage-notification-pro-note');
    const notificationProFields = document.getElementById('firephage-notification-pro-fields');
    const notificationWebhookStatus = document.getElementById('firephage-notification-webhook-status');
    const notificationSlackStatus = document.getElementById('firephage-notification-slack-status');
    const heroUpgradeButton = document.getElementById('firephage-hero-upgrade-button');
    let pollTimer = null;
    let scanIsRunning = false;
    let scanPollRequest = null;
    let currentScanState = {};
    let findingsPage = 1;
    let findingsPageSize = 25;
    let findingsSearchQuery = '';
    let pendingConfirmation = null;
    let selectedFindings = new Set();
    let restoreWarningDismissedForScanId = '';
    let freeTokenState = firephageAdmin.freeToken || { status: 'pending', email: '', marketingOptIn: false, requiresDecision: true, verificationToken: '' };
    let setupWizardState = firephageAdmin.setupWizard || { shouldOpen: false };
    let currentSetupWizardStep = 'token';
    let firewallRangeState = firewallRangeSelect ? (firewallRangeSelect.value || '24h') : '24h';
    const tabStorageKey = 'firephageActiveTab';
    let proTabState = {
        firewallLoaded: false,
        performanceLoaded: false,
        statusLoaded: false,
        connected: app.dataset.siteConnected === '1',
        paid: app.dataset.remoteProEnabled === '1',
        statusLoading: false,
    };
    let latestFirewallPayload = null;
    let latestPerformancePayload = null;
    let firewallRuleTabState = 'ip';

    const request = (action, payload = {}) => $.ajax({
        url: firephageAdmin.ajaxUrl,
        method: 'POST',
        timeout: 20000,
        data: {
            action,
            nonce: firephageAdmin.nonce,
            ...payload,
        },
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

    const ensureConfirmModalError = () => {
        if (!confirmModalBody) {
            return null;
        }

        let node = document.getElementById('firephage-confirm-modal-inline-error');

        if (!node) {
            node = document.createElement('div');
            node.id = 'firephage-confirm-modal-inline-error';
            node.className = 'firephage-modal-feedback is-error';
            node.hidden = true;
            confirmModalBody.prepend(node);
        }

        return node;
    };

    const clearConfirmModalError = () => {
        const node = document.getElementById('firephage-confirm-modal-inline-error');

        if (!node) {
            return;
        }

        node.hidden = true;
        node.textContent = '';
    };

    const showConfirmModalError = (message) => {
        const node = ensureConfirmModalError();

        if (!node) {
            showToast(message, true);
            return;
        }

        node.hidden = false;
        node.textContent = message;
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

    const firewallLoadingTargets = [
        firewallTotalRequests && firewallTotalRequests.closest('.firephage-pro-metric'),
        firewallRequestsBlocked && firewallRequestsBlocked.closest('.firephage-pro-metric'),
        firewallChallengeRate && firewallChallengeRate.closest('.firephage-pro-metric'),
        firewallBotPressure && firewallBotPressure.closest('.firephage-pro-metric'),
        firewallActivityBody && firewallActivityBody.closest('.firephage-pro-table'),
        firewallCountriesPanel,
        firewallIpsPanel,
        firewallIpRulesList && firewallIpRulesList.parentElement,
        firewallCountryRulesList && firewallCountryRulesList.parentElement,
        firewallContinentRulesList && firewallContinentRulesList.parentElement,
    ].filter(Boolean);

    const setFirewallLoading = (visible) => {
        firewallLoadingTargets.forEach((node) => {
            node.classList.toggle('is-loading', visible);
        });

        if (!visible) {
            return;
        }

        if (firewallActivityBody && firewallActivityBody.innerHTML.trim() === '') {
            firewallActivityBody.innerHTML = `
                <div class="firephage-pro-table__row firephage-pro-table__row--activity firephage-pro-table__row--skeleton"><span></span><span></span><span></span><span></span></div>
                <div class="firephage-pro-table__row firephage-pro-table__row--activity firephage-pro-table__row--skeleton"><span></span><span></span><span></span><span></span></div>
                <div class="firephage-pro-table__row firephage-pro-table__row--activity firephage-pro-table__row--skeleton"><span></span><span></span><span></span><span></span></div>
            `;
        }

        const ruleSkeleton = `
            <div class="firephage-pro-table__row firephage-pro-table__row--rules firephage-pro-table__row--skeleton"><span></span><span></span><span></span><span></span><span></span></div>
            <div class="firephage-pro-table__row firephage-pro-table__row--rules firephage-pro-table__row--skeleton"><span></span><span></span><span></span><span></span><span></span></div>
            <div class="firephage-pro-table__row firephage-pro-table__row--rules firephage-pro-table__row--skeleton"><span></span><span></span><span></span><span></span><span></span></div>
        `;

        if (firewallIpRulesList && firewallIpRulesList.innerHTML.trim() === '') {
            firewallIpRulesList.innerHTML = ruleSkeleton;
        }

        if (firewallCountryRulesList && firewallCountryRulesList.innerHTML.trim() === '') {
            firewallCountryRulesList.innerHTML = ruleSkeleton;
        }

        if (firewallContinentRulesList && firewallContinentRulesList.innerHTML.trim() === '') {
            firewallContinentRulesList.innerHTML = ruleSkeleton;
        }
    };

    const closeConfirmModal = () => {
        pendingConfirmation = null;
        clearConfirmModalError();

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
        clearConfirmModalError();
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
        previewModalContent.innerHTML = '';
    };

    const openPreviewModal = ({ file, content, truncated }) => {
        if (!previewModal || !previewModalTitle || !previewModalMeta || !previewModalContent) {
            return;
        }

        previewModalTitle.textContent = firephageAdmin.labels.previewFile || 'File Preview';
        previewModalMeta.textContent = truncated
            ? `${file} • ${firephageAdmin.labels.previewTruncated || 'Preview truncated to keep the browser responsive.'}`
            : file;
        const pre = document.createElement('pre');
        pre.className = 'firephage-preview-content';
        pre.textContent = content || '';
        previewModalContent.innerHTML = '';
        previewModalContent.appendChild(pre);
        previewModal.hidden = false;
    };

    const openCompareModal = ({ file, local, reference }) => {
        if (!previewModal || !previewModalTitle || !previewModalMeta || !previewModalContent) {
            return;
        }

        previewModalTitle.textContent = firephageAdmin.labels.compareTitle || 'Compare Files';

        const metaBits = [file];

        if (reference && reference.type && reference.version) {
            const typeLabel = reference.type.charAt(0).toUpperCase() + reference.type.slice(1);
            metaBits.push(`${typeLabel} ${reference.version}`);
        }

        if ((local && local.truncated) || (reference && reference.truncated)) {
            metaBits.push(firephageAdmin.labels.previewTruncated || 'Preview truncated to keep the browser responsive.');
        }

        previewModalMeta.textContent = metaBits.join(' • ');
        previewModalContent.innerHTML = '';

        const compare = document.createElement('div');
        compare.className = 'firephage-compare-grid';
        const localLines = String(local && local.content ? local.content : '').split('\n');
        const referenceLines = String(reference && reference.content ? reference.content : '').split('\n');
        const totalLines = Math.max(localLines.length, referenceLines.length);

        const makePane = (label, lines, otherLines) => {
            const pane = document.createElement('section');
            pane.className = 'firephage-compare-pane';

            const heading = document.createElement('h4');
            heading.className = 'firephage-compare-pane__title';
            heading.textContent = label;

            const body = document.createElement('div');
            body.className = 'firephage-compare-lines';

            for (let index = 0; index < totalLines; index += 1) {
                const line = lines[index] ?? '';
                const otherLine = otherLines[index] ?? '';
                const row = document.createElement('div');
                row.className = 'firephage-compare-line';

                if (line !== otherLine) {
                    row.classList.add('is-different');
                }

                const lineNumber = document.createElement('span');
                lineNumber.className = 'firephage-compare-line__number';
                lineNumber.textContent = `${index + 1}`;

                const lineContent = document.createElement('code');
                lineContent.className = 'firephage-compare-line__content';
                lineContent.textContent = line === '' ? ' ' : line;

                row.appendChild(lineNumber);
                row.appendChild(lineContent);
                body.appendChild(row);
            }

            pane.appendChild(heading);
            pane.appendChild(body);

            return pane;
        };

        compare.appendChild(makePane(firephageAdmin.labels.localFile || 'Local file', localLines, referenceLines));
        compare.appendChild(makePane(firephageAdmin.labels.officialReference || 'Official reference', referenceLines, localLines));
        previewModalContent.appendChild(compare);
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

    const dismissSetupWizard = () => {
        setupWizardState.shouldOpen = false;

        request('firephage_dismiss_setup_wizard')
            .always(() => {
                closeSetupWizardModal();
            });
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
        setSetupWizardStep('token');
        setupWizardModal.hidden = false;
    };

    const setSetupWizardStep = (step) => {
        currentSetupWizardStep = step;

        if (!setupWizardForm) {
            return;
        }

        setupWizardForm.querySelectorAll('[data-setup-step]').forEach((node) => {
            if (!(node instanceof HTMLElement)) {
                return;
            }

            node.hidden = node.dataset.setupStep !== step;
        });

        document.querySelectorAll('[data-step-indicator]').forEach((node) => {
            if (!(node instanceof HTMLElement)) {
                return;
            }

            node.classList.toggle('is-active', node.dataset.stepIndicator === step);
        });
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

    const restoreSingleIntegrityFile = (button) => {
        button.setAttribute('disabled', 'disabled');

        request('firephage_restore_file', {
            file: button.dataset.file || '',
            source: button.dataset.source || '',
        })
            .done((response) => {
                if (response.success) {
                    renderScanState(response.data.state);
                    showToast(response.data.message || 'The official file was restored.');
                } else {
                    showToast((response.data && response.data.message) || 'Unable to restore the file.', true);
                }
            })
            .fail((xhr) => {
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to restore the file.', true);
            })
            .always(() => {
                button.removeAttribute('disabled');
                closeConfirmModal();
            });
    };

    const restoreAllIntegrityFiles = (button) => {
        button.setAttribute('disabled', 'disabled');

        request('firephage_restore_all_integrity_files')
            .done((response) => {
                if (response.success) {
                    findingsPage = 1;
                    renderScanState(response.data.state);
                    showToast(response.data.message || 'Modified files restored.');
                } else {
                    showToast((response.data && response.data.message) || 'Unable to restore the modified files.', true);
                }
            })
            .fail((xhr) => {
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to restore the modified files.', true);
            })
            .always(() => {
                button.removeAttribute('disabled');
                closeConfirmModal();
            });
    };

    const confirmRestoreAction = ({ title, body, button, onConfirm, fileCount = 0 }) => {
        const scanId = String((currentScanState && currentScanState.scan_id) || '');

        if (scanId && restoreWarningDismissedForScanId === scanId) {
            onConfirm(button);
            return;
        }

        const checkboxId = `firephage-restore-acknowledge-${Date.now()}`;
        const countMarkup = fileCount > 0
            ? `<p><strong>${escapeHtml(firephageAdmin.labels.confirmRestoreCountLabel || 'Files ready to restore')}:</strong> ${fileCount}</p>`
            : '';

        openConfirmModal({
            title,
            body: `<p>${escapeHtml(body)}</p>${countMarkup}<p><strong>${escapeHtml(firephageAdmin.labels.confirmRestoreBackup || 'Create a backup before restoring files.')}</strong></p><p class="firephage-note">${escapeHtml(firephageAdmin.labels.confirmRestoreWarning || 'Restoring official files will overwrite local edits.')}</p><label class="firephage-confirm-check"><input type="checkbox" id="${checkboxId}" /> <span>${escapeHtml(firephageAdmin.labels.confirmRestoreAcknowledge || 'I understand this will overwrite local changes. Do not show this warning again until the next scan.')}</span></label>`,
            actionLabel: firephageAdmin.labels.restoreFile || 'Restore',
            danger: false,
            onConfirm: () => {
                const checkbox = document.getElementById(checkboxId);

                if (!(checkbox instanceof HTMLInputElement) || !checkbox.checked) {
                    showConfirmModalError(firephageAdmin.labels.confirmRestoreAcknowledgeRequired || 'Please check the confirmation box before restoring files.');

                    if (confirmModalSubmit) {
                        confirmModalSubmit.disabled = false;
                    }

                    return;
                }

                if (scanId) {
                    restoreWarningDismissedForScanId = scanId;
                }

                onConfirm(button);
            },
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

    const countryNameMap = {
        AU: 'Australia',
        BR: 'Brazil',
        CA: 'Canada',
        DE: 'Germany',
        ES: 'Spain',
        FR: 'France',
        GA: 'Gabon',
        GB: 'United Kingdom',
        IN: 'India',
        JP: 'Japan',
        KR: 'South Korea',
        NL: 'Netherlands',
        RS: 'Serbia',
        SE: 'Sweden',
        SG: 'Singapore',
        US: 'United States',
        ZA: 'South Africa',
    };

    const firewallContinentFallbackOptions = {
        AF: 'Africa',
        AN: 'Antarctica',
        AS: 'Asia',
        EU: 'Europe',
        NA: 'North America',
        OC: 'Oceania',
        SA: 'South America',
    };

    const countryFlagEmoji = (countryCode) => {
        const code = String(countryCode || '').trim().toUpperCase();

        if (!/^[A-Z]{2}$/.test(code)) {
            return '';
        }

        return String.fromCodePoint(code.charCodeAt(0) + 127397, code.charCodeAt(1) + 127397);
    };

    const countryLabel = (countryCode) => {
        const code = String(countryCode || '').trim().toUpperCase();

        if (!code) {
            return '--';
        }

        return countryNameMap[code] || code;
    };

    const firewallOptionDisplay = (value, label) => {
        const code = String(value || '').trim().toUpperCase();
        const text = String(label || '').trim();

        if (!code) {
            return text;
        }

        if (!text || text.toUpperCase() === code) {
            return code;
        }

        return `${text} (${code})`;
    };

    const normalizeFirewallOptionInput = (input, options = {}) => {
        const raw = String(input || '').trim();

        if (!raw) {
            return '';
        }

        const directCode = raw.toUpperCase();

        if (options[directCode]) {
            return directCode;
        }

        const trailingCode = raw.match(/\(([A-Za-z]{2,3})\)\s*$/);

        if (trailingCode) {
            return String(trailingCode[1] || '').toUpperCase();
        }

        const found = Object.entries(options).find(([, label]) => String(label || '').trim().toLowerCase() === raw.toLowerCase());

        return found ? String(found[0] || '').toUpperCase() : directCode;
    };

    const topCountryRows = (rows = [], totalRequests = 0) => {
        if (!Array.isArray(rows) || !rows.length) {
            return '<p class="firephage-empty">No country traffic data yet.</p>';
        }

        return `<div class="firephage-pro-table">
            ${rows.map((row) => {
                const requests = Number(row.requests || 0);
                const share = totalRequests > 0 ? Math.min(100, Math.round((requests / totalRequests) * 100)) : 0;
                const code = String(row.country || '').toUpperCase();
                const flag = countryFlagEmoji(code);
                const label = countryLabel(code);

                return `<div class="firephage-pro-table__row firephage-pro-table__row--traffic">
                    <span class="firephage-traffic-country">
                        <span class="firephage-traffic-country__flag">${escapeHtml(flag)}</span>
                        <span class="firephage-traffic-country__meta">
                            <strong>${escapeHtml(label)}</strong>
                            <small>${escapeHtml(code || '--')}</small>
                        </span>
                    </span>
                    <span class="firephage-traffic-country__stats">
                        <strong>${requests}</strong>
                        <small>${share}% of recent traffic</small>
                    </span>
                </div>`;
            }).join('')}
        </div>`;
    };

    const ensureSearchableSelect = (select, placeholder) => {
        if (!select) {
            return null;
        }

        if (typeof window.Choices !== 'function') {
            return null;
        }

        if (select.dataset.firephageChoicesReady === '1' && select.firephageChoicesInstance) {
            return select.firephageChoicesInstance;
        }

        const instance = new window.Choices(select, {
            searchEnabled: true,
            searchResultLimit: 8,
            shouldSort: false,
            itemSelectText: '',
            allowHTML: false,
            placeholder: true,
            placeholderValue: placeholder,
            searchPlaceholderValue: placeholder,
            noResultsText: 'No matches found',
            noChoicesText: 'No options available',
        });

        select.dataset.firephageChoicesReady = '1';
        select.firephageChoicesInstance = instance;

        if (select === firewallBlockCountrySelect) {
            firewallCountryChoices = instance;
        }

        if (select === firewallBlockContinentSelect) {
            firewallContinentChoices = instance;
        }

        return instance;
    };

    const renderSelectOptions = (select, options, placeholder) => {
        if (!select) {
            return;
        }

        const entries = Object.entries(options || {}).map(([value, label]) => ({
            value,
            label: firewallOptionDisplay(value, label),
            selected: String(select.value || '').toUpperCase() === String(value || '').toUpperCase(),
        }));

        const instance = ensureSearchableSelect(select, placeholder);

        if (instance) {
            instance.clearStore();
            instance.setChoices(
                [{ value: '', label: placeholder, selected: !select.value, disabled: false }].concat(entries),
                'value',
                'label',
                true
            );

            return;
        }

        select.innerHTML = `<option value="">${escapeHtml(placeholder)}</option>${entries.map((entry) => `<option value="${escapeHtml(entry.value)}"${entry.selected ? ' selected' : ''}>${escapeHtml(entry.label)}</option>`).join('')}`;
    };

    const ruleStatusLabel = (status) => {
        const normalized = String(status || '').toLowerCase();

        if (normalized === 'active') {
            return 'Enabled';
        }

        if (normalized === 'removed') {
            return 'Disabled';
        }

        if (normalized === 'pending') {
            return 'Pending';
        }

        if (normalized === 'failed') {
            return 'Failed';
        }

        return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : '--';
    };

    const firewallRuleRows = (rows = [], emptyMessage = 'No rules configured yet.') => {
        if (!Array.isArray(rows) || !rows.length) {
            return `<div class="firephage-pro-table__row firephage-pro-table__row--rules firephage-pro-table__row--empty"><span class="firephage-table-empty-cell">${escapeHtml(emptyMessage)}</span></div>`;
        }

        return rows.map((row) => {
            const status = String(row.status || '');
            const enabled = status === 'active' || status === 'pending';
            const target = String(row.target || '--');
            const targetLabel = String(row.target_label || target || '--');
            const targetList = Array.isArray(row.target_list) ? row.target_list.filter(Boolean) : [];
            const targetDetail = targetList.length ? targetList.join(', ') : '';
            const canToggle = row.can_toggle !== false;
            const canRemove = row.can_remove !== false;
            const actionButtons = [];

            if (canToggle) {
                actionButtons.push(`<button type="button" class="button-link firephage-link-button firephage-toggle-firewall-rule" data-rule-id="${escapeHtml(row.id || '')}" data-rule-enabled="${enabled ? '0' : '1'}">${enabled ? 'Disable' : 'Enable'}</button>`);
            }

            if (canRemove) {
                actionButtons.push(`<button type="button" class="button-link firephage-link-button firephage-remove-firewall-rule" data-rule-id="${escapeHtml(row.id || '')}" data-rule-target="${escapeHtml(target)}" data-target-code="${escapeHtml(row.target_code || '')}">${canToggle ? 'Delete' : 'Remove'}</button>`);
            }

            return `<div class="firephage-pro-table__row firephage-pro-table__row--rules">
                <span>
                    <strong>${escapeHtml(targetLabel)}</strong>
                    ${targetDetail ? `<small class="firephage-rule-target-list">${escapeHtml(targetDetail)}</small>` : ''}
                </span>
                <span>${escapeHtml(String(row.action || '').toUpperCase())}</span>
                <span>${escapeHtml(ruleStatusLabel(status))}</span>
                <span>${escapeHtml(row.source || 'Edge')}</span>
                <span class="firephage-rule-actions">
                    ${actionButtons.join('')}
                </span>
            </div>`;
        }).join('');
    };

    const renderFirewallRulePanels = (rules = []) => {
        const allRules = Array.isArray(rules) ? rules : [];
        const counts = {
            ip: allRules.filter((row) => String(row.type || '') === 'ip').length,
            country: allRules.filter((row) => String(row.type || '') === 'country').length,
            continent: allRules.filter((row) => String(row.type || '') === 'continent').length,
        };

        if (firewallIpRulesList) {
            firewallIpRulesList.innerHTML = firewallRuleRows(allRules.filter((row) => String(row.type || '') === 'ip'), 'No IP access rules configured yet.');
        }

        if (firewallCountryRulesList) {
            firewallCountryRulesList.innerHTML = firewallRuleRows(allRules.filter((row) => String(row.type || '') === 'country'), 'No country blocks configured yet.');
        }

        if (firewallContinentRulesList) {
            firewallContinentRulesList.innerHTML = firewallRuleRows(allRules.filter((row) => String(row.type || '') === 'continent'), 'No continent blocks configured yet.');
        }

        if (!counts[firewallRuleTabState]) {
            if (counts.country) {
                setFirewallRuleTab('country');
            } else if (counts.continent) {
                setFirewallRuleTab('continent');
            } else if (counts.ip) {
                setFirewallRuleTab('ip');
            }
        }
    };

    const setFirewallRuleTab = (tab) => {
        firewallRuleTabState = tab;

        firewallRuleTabButtons.forEach((button) => {
            button.classList.toggle('is-active', button.dataset.firewallRuleTab === tab);
        });

        firewallRulePanels.forEach((panel) => {
            panel.hidden = panel.dataset.firewallRulePanel !== tab;
        });
    };

    const topIpRows = (rows = []) => {
        if (!Array.isArray(rows) || !rows.length) {
            return '<p class="firephage-empty">Top IPs will appear after FirePhage receives detailed edge request logs for this site.</p>';
        }

        return `<div class="firephage-pro-table">
            ${rows.map((row) => {
                const code = String(row.country || '').toUpperCase();
                const flag = countryFlagEmoji(code);
                const label = countryLabel(code);

                return `<div class="firephage-pro-table__row firephage-pro-table__row--traffic">
                    <span class="firephage-traffic-country" title="${escapeHtml(label)}">
                        <span class="firephage-traffic-country__flag">${escapeHtml(flag)}</span>
                        <span class="firephage-traffic-country__meta">
                            <strong>${escapeHtml(row.ip || '--')}</strong>
                        </span>
                    </span>
                    <span class="firephage-traffic-country__stats">
                        <strong>${row.requests || 0}</strong>
                        <small>${row.blocked || 0} blocked</small>
                    </span>
                </div>`;
            }).join('')}
        </div>`;
    };

    const renderFirewallSummary = (payload) => {
        if (!firewallSummaryText || !firewallConnectionNote) {
            return;
        }

        latestFirewallPayload = payload;

        if (!payload.connected) {
            setBadge(firewallStatusBadge, 'Connect', 'neutral');
            if (firewallActivityBadge) {
                setBadge(firewallActivityBadge, 'Waiting', 'neutral');
            }
            if (firewallControlsBadge) {
                setBadge(firewallControlsBadge, 'Waiting', 'neutral');
            }
            if (firewallInsightsBadge) {
                setBadge(firewallInsightsBadge, 'Preview', 'neutral');
            }
            firewallSummaryText.textContent = 'Connect to view live firewall analytics.';
            firewallConnectionNote.textContent = payload.message || 'Connect FirePhage to load live traffic filtering and edge analytics for this site.';
            if (firewallControlsNote) {
                firewallControlsNote.textContent = 'Connect FirePhage to review managed protection settings for this site.';
            }
            if (firewallInsightsSummary) {
                firewallInsightsSummary.textContent = 'Live traffic insights become available after connecting FirePhage. This preview shows the kinds of patterns you can review once edge analytics are enabled.';
            }
            if (firewallInsightsNote) {
                firewallInsightsNote.textContent = 'Preview values are illustrative only. Connect FirePhage to load real firewall events and live traffic patterns for this site.';
            }
            if (firewallActivityBody) {
                firewallActivityBody.innerHTML = '';
            }
            renderFirewallRulePanels([]);
            return;
        }

        const statusTone = payload.pro_enabled ? 'good' : 'warning';
        setBadge(firewallStatusBadge, payload.pro_enabled ? 'Live' : 'Plan Required', statusTone);
        if (firewallActivityBadge) {
            setBadge(firewallActivityBadge, payload.pro_enabled ? 'Live' : 'Locked', payload.pro_enabled ? 'good' : 'neutral');
        }
        if (firewallControlsBadge) {
            setBadge(firewallControlsBadge, payload.pro_enabled ? 'Live snapshot' : 'Plan Required', payload.pro_enabled ? 'good' : 'warning');
        }
        if (firewallInsightsBadge) {
            setBadge(firewallInsightsBadge, payload.pro_enabled ? 'Live' : 'Preview', payload.pro_enabled ? 'good' : 'neutral');
        }

        firewallRangeState = payload.metrics && payload.metrics.range === '7d' ? '7d' : '24h';
        if (firewallRangeSelect && firewallRangeSelect.value !== firewallRangeState) {
            firewallRangeSelect.value = firewallRangeState;
        }
        if (firewallRangeSelect) {
            firewallRangeSelect.disabled = !payload.pro_enabled;
        }

        firewallSummaryText.textContent = payload.pro_enabled
            ? `${payload.status.label} on ${payload.site.domain}. WAF status: ${payload.status.waf_status}. Showing ${firewallRangeState === '7d' ? 'the last 7 days' : 'the last 24 hours'}.`
            : 'This WordPress site is currently using local plugin safeguards only. Connect a paid FirePhage site plan to load edge firewall telemetry and managed access controls here.';
        firewallConnectionNote.textContent = payload.pro_enabled
            ? 'Local plugin safeguards still protect login attempts and XML-RPC traffic on this WordPress site. FirePhage WAF adds the edge-side layer before traffic reaches WordPress.'
            : (payload.message || firephageAdmin.labels.proInactive);

        if (firewallTotalRequests) {
            firewallTotalRequests.textContent = payload.metrics && payload.metrics.total_requests !== undefined ? Number(payload.metrics.total_requests || 0).toLocaleString() : '';
        }
        if (firewallRequestsBlocked) {
            firewallRequestsBlocked.textContent = payload.metrics && payload.metrics.requests_blocked !== undefined ? Number(payload.metrics.requests_blocked || 0).toLocaleString() : '';
        }
        if (firewallChallengeRate) {
            firewallChallengeRate.textContent = payload.metrics && payload.metrics.challenge_rate !== undefined ? `${payload.metrics.challenge_rate}%` : '';
        }
        if (firewallBotPressure) {
            firewallBotPressure.textContent = payload.metrics && payload.metrics.bot_pressure !== undefined ? `${payload.metrics.bot_pressure}%` : '';
        }
        if (firewallControlsNote) {
            firewallControlsNote.textContent = payload.pro_enabled
                ? 'These settings are managed in FirePhage and shown here as a live snapshot.'
                : 'An active paid site plan is required before managed edge controls appear here.';
        }
        if (firewallProtectionMode) {
            firewallProtectionMode.textContent = payload.controls.protection_mode || 'Adaptive WAF';
        }

        firewallCountryOptionMap = (payload.options && payload.options.countries) || {};
        firewallContinentOptionMap = Object.assign({}, firewallContinentFallbackOptions, (payload.options && payload.options.continents) || {});
        renderSelectOptions(firewallBlockCountrySelect, firewallCountryOptionMap, 'Search and choose a country...');
        renderSelectOptions(firewallBlockContinentSelect, firewallContinentOptionMap, 'Search and choose a continent...');

        [firewallBlockIpInput, firewallBlockIpButton, firewallAllowIpInput, firewallAllowIpButton, firewallBlockCountrySelect, firewallBlockCountryButton, firewallBlockContinentSelect, firewallBlockContinentButton].forEach((node) => {
            if (node) {
                node.disabled = !payload.pro_enabled;
            }
        });

        renderFirewallRulePanels(payload.rules || []);

        if (firewallActivityBody && Array.isArray(payload.activity)) {
            firewallActivityBody.innerHTML = payload.activity.length
                ? payload.activity.map((row) => `<div class="firephage-pro-table__row firephage-pro-table__row--activity"><span>${row.timestamp ? new Date(row.timestamp).toLocaleString() : '--'}</span><span>${row.action || 'ALLOW'}</span><span>${row.path || '/'}</span><span>${escapeHtml([row.method || 'GET', row.country || '--', row.ip || '-'].join(' • '))}</span></div>`).join('')
                : '';
        }

        if (firewallInsightsSummary) {
            firewallInsightsSummary.textContent = payload.pro_enabled
                ? `Live traffic insights for ${payload.site.domain}. Review total requests, top countries, and top IPs from recent edge telemetry.`
                : 'Live traffic insights become available after connecting FirePhage. This preview shows the kinds of patterns you can review once edge analytics are enabled.';
        }

        if (firewallCountriesPanel) {
            firewallCountriesPanel.innerHTML = payload.pro_enabled
                ? `<h4>Top countries</h4>${topCountryRows((payload.insights && payload.insights.top_countries) || [], payload.metrics.total_requests || 0)}`
                : `<h4>Traffic by country</h4>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>United States</span><span>72%</span></div><div class="firephage-preview-bar__track"><span style="width:72%;"></span></div></div>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>Germany</span><span>41%</span></div><div class="firephage-preview-bar__track"><span style="width:41%;"></span></div></div>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>United Kingdom</span><span>33%</span></div><div class="firephage-preview-bar__track"><span style="width:33%;"></span></div></div>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>Japan</span><span>19%</span></div><div class="firephage-preview-bar__track"><span style="width:19%;"></span></div></div>`;
        }

        if (firewallIpsPanel) {
            firewallIpsPanel.innerHTML = payload.pro_enabled
                ? `<h4>Top IPs</h4>${topIpRows((payload.insights && payload.insights.top_ips) || [])}`
                : `<h4>Top IPs</h4>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>Allowed requests</span><span>88%</span></div><div class="firephage-preview-bar__track"><span style="width:88%;"></span></div></div>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>Blocked requests</span><span>24%</span></div><div class="firephage-preview-bar__track"><span style="width:24%;"></span></div></div>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>Challenge rate</span><span>17%</span></div><div class="firephage-preview-bar__track"><span style="width:17%;"></span></div></div>
                    <div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>Bot activity</span><span>29%</span></div><div class="firephage-preview-bar__track"><span style="width:29%;"></span></div></div>`;
        }

        if (firewallInsightsNote) {
            firewallInsightsNote.textContent = payload.pro_enabled
                ? 'Live edge analytics are loaded from your connected FirePhage site.'
                : 'Preview values are illustrative only. Connect FirePhage to load real firewall events and live traffic patterns for this site.';
        }

        if (firewallUpgradeCard) {
            firewallUpgradeCard.style.display = payload.pro_enabled ? 'none' : '';
        }

        if (firewallPreviewCard) {
            firewallPreviewCard.style.display = '';
        }
    };

    const renderPerformanceSummary = (payload) => {
        if (!performanceSummaryText || !performanceConnectionNote) {
            return;
        }

        if (!payload.connected) {
            latestPerformancePayload = payload;
            setBadge(performanceStatusBadge, 'Connect', 'neutral');
            performanceSummaryText.textContent = 'Connect to load performance data.';
            performanceConnectionNote.textContent = payload.message || 'Upgrade required to manage CDN and cache settings from WordPress.';
            return;
        }

        const tone = payload.pro_enabled ? 'good' : 'warning';
        latestPerformancePayload = payload;
        setBadge(performanceStatusBadge, payload.pro_enabled ? 'Live' : 'Plan Required', tone);
        performanceSummaryText.textContent = payload.pro_enabled
            ? `${payload.summary.requests_24h || 0} requests over the last 24 hours. Cache hit ratio: ${payload.summary.cache_hit_ratio || 0}%.`
            : 'Connect a paid FirePhage site plan to load live CDN, cache, and troubleshooting controls from WordPress.';
        performanceConnectionNote.textContent = payload.pro_enabled ? 'Live CDN and cache telemetry is loaded from your connected FirePhage site.' : (payload.message || firephageAdmin.labels.proInactive);

        if (performanceRouting) {
            performanceRouting.value = payload.summary.edge_enabled ? 'Traffic is routed through FirePhage edge' : 'Routing not active yet';
        }
        if (performanceTroubleshooting) {
            performanceTroubleshooting.value = payload.settings.troubleshooting_mode ? 'Enabled' : 'Disabled';
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
        if (performancePurgeCacheButton) {
            performancePurgeCacheButton.disabled = !payload.pro_enabled;
        }
        if (performanceToggleTroubleshootingButton) {
            performanceToggleTroubleshootingButton.disabled = !payload.pro_enabled;
            performanceToggleTroubleshootingButton.textContent = payload.settings.troubleshooting_mode ? 'Disable Troubleshooting Mode' : 'Enable Troubleshooting Mode';
        }
    };

    const renderLocalFirewallOnlyState = () => {
        renderFirewallSummary({
            connected: proTabState.connected,
            pro_enabled: false,
            message: firephageAdmin.labels.proInactive || 'A paid FirePhage site plan is required to load live firewall data.',
            status: {
                label: 'Local only',
                waf_status: 'Not enabled',
            },
            site: {
                domain: window.location.hostname || 'this site',
            },
            metrics: {
                range: firewallRangeState,
            },
            controls: {
                protection_mode: 'Local plugin safeguards',
            },
            options: {
                countries: {},
                continents: {},
            },
            rules: [],
            activity: [],
            insights: {
                top_countries: [],
                top_ips: [],
            },
        });
    };

    const ensureProStatus = (onReady = null) => {
        if (proTabState.statusLoaded) {
            if (typeof onReady === 'function') {
                onReady();
            }
            return;
        }

        if (proTabState.statusLoading) {
            return;
        }

        proTabState.statusLoading = true;
        request('firephage_fetch_plugin_status')
            .done((response) => {
                if (response.success) {
                    const billing = response.data && response.data.billing ? response.data.billing : {};
                    proTabState.connected = !!response.data.connected;
                    proTabState.paid = !!(response.data.connected && billing && billing.pro_enabled);
                    proTabState.statusLoaded = true;
                    applyNotificationProState(response.data);
                    applyBruteforceProState(response.data);
                    if (typeof onReady === 'function') {
                        onReady();
                    }
                } else {
                    proTabState.statusLoaded = false;
                }
            })
            .fail(() => {
                proTabState.statusLoaded = false;
            })
            .always(() => {
                proTabState.statusLoading = false;
            });
    };

    const refreshFirewallSummary = () => {
        if (!proTabState.paid) {
            renderLocalFirewallOnlyState();
            return $.Deferred().resolve().promise();
        }

        setFirewallLoading(true);

        return request('firephage_fetch_firewall_summary', {
            range: firewallRangeState,
        })
            .done((response) => {
                try {
                    if (response.success) {
                        renderFirewallSummary(response.data);
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to load firewall data.', true);
                    }
                } catch (_error) {
                    showToast('Unable to render firewall data.', true);
                }
            })
            .fail((xhr, textStatus) => {
                const fallback = textStatus === 'timeout'
                    ? 'Loading firewall data took too long and was cancelled.'
                    : 'Unable to load firewall data.';
                showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || fallback, true);
            })
            .always(() => {
                setFirewallLoading(false);
            });
    };

    const refreshPerformanceSummary = () => request('firephage_fetch_performance_summary')
        .done((response) => {
            if (response.success) {
                renderPerformanceSummary(response.data);
            }
        });

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
        const wafManaged = !!summary.waf_managed;
        const overviewText = wafManaged ? 'WAF Managed' : (!summary.enabled ? 'Disabled' : ((summary.active_lockouts_count || 0) > 0 ? 'Active Lockouts' : 'Enabled'));

        setBadge(bruteForceOverviewBadge, overviewText, badgeTone);
        setBadge(bruteForceStatusBadge, wafManaged ? 'WAF Managed' : (summary.enabled ? 'Enabled' : 'Disabled'), badgeTone);

        if (bruteForceSnapshotBadge) {
            setBadge(bruteForceSnapshotBadge, wafManaged ? 'Edge' : 'Local', 'neutral');
        }

        if (bruteForceOverviewSummary) {
            bruteForceOverviewSummary.textContent = summary.summary || '';
        }

        if (bruteForceSummaryText) {
            bruteForceSummaryText.textContent = summary.summary || '';
        }

        if (bruteForceThreshold) {
            bruteForceThreshold.textContent = wafManaged ? 'WAF managed' : `${summary.threshold || 0}`;
        }

        if (bruteForceWindow) {
            bruteForceWindow.textContent = wafManaged ? 'Protected at edge' : `${summary.window_minutes || 0}m / ${summary.lockout_minutes || 0}m`;
        }

        if (bruteForceActiveCount) {
            bruteForceActiveCount.textContent = wafManaged ? 'Disabled' : `${summary.active_lockouts_count || 0}`;
        }

        if (bruteForceXmlrpcNote) {
            bruteForceXmlrpcNote.textContent = wafManaged
                ? 'XML-RPC authentication is protected by FirePhage WAF rate limiting.'
                : (summary.protect_xmlrpc
                    ? 'XML-RPC authentication is currently covered by the same rate-limit rules.'
                    : 'XML-RPC authentication is currently excluded from local brute-force protection.');
        }

        if (bruteForceLocalPanel) {
            bruteForceLocalPanel.hidden = wafManaged;
        }

        if (bruteForceManagedPanel) {
            bruteForceManagedPanel.hidden = !wafManaged;
        }

        if (bruteForceLocalHistory) {
            bruteForceLocalHistory.hidden = false;
        }

        if (bruteForceActiveBadge) {
            setBadge(bruteForceActiveBadge, wafManaged ? 'WAF managed' : `${summary.active_lockouts_count || 0} active`, wafManaged ? 'good' : ((summary.active_lockouts_count || 0) > 0 ? 'warning' : 'neutral'));
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

    const applyNotificationProState = (payload = {}) => {
        const billing = payload && payload.billing ? payload.billing : {};
        const paid = !! (payload.connected && billing && billing.pro_enabled);

        if (notificationProBadge) {
            setBadge(notificationProBadge, paid ? 'Included' : 'Plan Required', paid ? 'good' : 'warning');
        }

        if (notificationProNote) {
            notificationProNote.textContent = paid
                ? 'Slack and webhook routing are managed in FirePhage. The status below reflects your current dashboard setup.'
                : 'Webhook and Slack alerts are available after connecting a paid FirePhage plan.';
        }

        if (notificationProFields) {
            notificationProFields.classList.toggle('firephage-pro-fieldset--disabled', !paid);
        }

        const alertChannels = payload && payload.alert_channels ? payload.alert_channels : {};
        const webhookEnabled = !! (alertChannels.webhook && alertChannels.webhook.enabled && alertChannels.webhook.configured);
        const slackEnabled = !! (alertChannels.slack && alertChannels.slack.enabled && alertChannels.slack.configured);

        if (notificationWebhookStatus) {
            notificationWebhookStatus.textContent = paid ? (webhookEnabled ? 'Enabled' : 'Not configured') : 'Locked';
        }

        if (notificationSlackStatus) {
            notificationSlackStatus.textContent = paid ? (slackEnabled ? 'Enabled' : 'Not configured') : 'Locked';
        }

        if (heroUpgradeButton) {
            heroUpgradeButton.hidden = paid;
        }
    };

    const applyBruteforceProState = (payload = {}) => {
        const billing = payload && payload.billing ? payload.billing : {};
        const paid = !! (payload.connected && billing && billing.pro_enabled);

        if (!paid) {
            return;
        }

        if (bruteForceOverviewBadge) {
            setBadge(bruteForceOverviewBadge, 'WAF Managed', 'good');
        }

        if (bruteForceStatusBadge) {
            setBadge(bruteForceStatusBadge, 'WAF Managed', 'good');
        }

        if (bruteForceSnapshotBadge) {
            setBadge(bruteForceSnapshotBadge, 'Edge', 'neutral');
        }

        if (bruteForceOverviewSummary) {
            bruteForceOverviewSummary.textContent = 'FirePhage WAF is now protecting WordPress logins and XML-RPC at the edge. The local PHP lockout layer is standing down to avoid duplicate enforcement.';
        }

        if (bruteForceSummaryText) {
            bruteForceSummaryText.textContent = 'FirePhage WAF is now protecting WordPress logins and XML-RPC at the edge. The local PHP lockout layer is standing down to avoid duplicate enforcement.';
        }

        if (bruteForceThreshold) {
            bruteForceThreshold.textContent = 'WAF managed';
        }

        if (bruteForceWindow) {
            bruteForceWindow.textContent = 'Protected at edge';
        }

        if (bruteForceActiveCount) {
            bruteForceActiveCount.textContent = 'Disabled';
        }

        if (bruteForceXmlrpcNote) {
            bruteForceXmlrpcNote.textContent = 'XML-RPC authentication is protected by FirePhage WAF rate limiting.';
        }

        if (bruteForceLocalPanel) {
            bruteForceLocalPanel.hidden = true;
        }

        if (bruteForceManagedPanel) {
            bruteForceManagedPanel.hidden = false;
        }

        if (bruteForceLocalHistory) {
            bruteForceLocalHistory.hidden = false;
        }

        if (bruteForceActiveBadge) {
            setBadge(bruteForceActiveBadge, 'WAF managed', 'good');
        }
    };

    const maybeLoadProTab = (tabId) => {
        ensureProStatus(() => {
            if (tabId === 'firewall' && !proTabState.paid) {
                renderLocalFirewallOnlyState();
            }

            if (tabId === 'performance' && !proTabState.paid) {
                renderPerformanceSummary({
                    connected: proTabState.connected,
                    pro_enabled: false,
                    message: firephageAdmin.labels.proInactive || 'Upgrade required to manage CDN and cache settings from WordPress.',
                    summary: {},
                    settings: {
                        troubleshooting_mode: false,
                        smart_image_optimization: false,
                        edge_compression: false,
                    },
                    cache_rules: [],
                });
            }
        });

        if (tabId === 'firewall' && !proTabState.firewallLoaded && proTabState.paid) {
            proTabState.firewallLoaded = true;
            setFirewallLoading(true);
            request('firephage_fetch_firewall_summary')
                .done((response) => {
                    try {
                        if (response.success) {
                            renderFirewallSummary(response.data);
                        } else {
                            proTabState.firewallLoaded = false;
                            showToast((response.data && response.data.message) || 'Unable to load firewall data.', true);
                        }
                    } catch (_error) {
                        proTabState.firewallLoaded = false;
                        showToast('Unable to render firewall data.', true);
                    }
                })
                .fail((xhr, textStatus) => {
                    proTabState.firewallLoaded = false;
                    const fallback = textStatus === 'timeout'
                        ? 'Loading firewall data took too long and was cancelled.'
                        : 'Unable to load firewall data.';
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || fallback, true);
                })
                .always(() => {
                    setFirewallLoading(false);
                });
        }

        if (tabId === 'performance' && !proTabState.performanceLoaded && proTabState.paid) {
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
        const officialChecksumMismatches = Number(state.official_checksum_mismatches || 0);
        const baselineChanges = Number(state.baseline_changes || 0);
        const integritySummary = baselineChanges > 0
            ? `Official checksum mismatches: ${officialChecksumMismatches}. Local baseline changes: ${baselineChanges}`
            : `Official checksum mismatches: ${officialChecksumMismatches}`;

        if (state.status === 'idle') {
            return 'The scanner is idle. Start a background scan to verify repository integrity and review untrusted code paths.';
        }

        if (state.status === 'discovering') {
            return `${scanModeLabel}: discovering candidate files: ${state.discovered_files} found so far.`;
        }

        if (state.status === 'stopped') {
            return `${scanModeLabel} cancelled at ${state.scanned_files} of ${state.discovered_files} discovered files. Trusted: ${state.trusted_files}. Clean custom files: ${state.clean_files || 0}. Skipped: ${state.skipped_files || 0}. ${integritySummary}. Malicious: ${state.suspicious_files}. Use Resume Scan to continue from the saved position.`;
        }

        if (state.status === 'completed') {
            return `${scanModeLabel} completed. ${state.scanned_files} files scanned, ${state.trusted_files} trusted, ${state.clean_files || 0} clean custom files, ${state.skipped_files || 0} skipped, ${integritySummary}, ${state.suspicious_files} malicious.`;
        }

        if (state.status === 'failed') {
            return `Scan failed: ${state.last_error || 'Unknown error'}`;
        }

        return `${scanModeLabel}: scanning ${state.scanned_files} of ${state.discovered_files} discovered files. Trusted: ${state.trusted_files}. Clean custom files: ${state.clean_files || 0}. Skipped: ${state.skipped_files || 0}. ${integritySummary}. Malicious: ${state.suspicious_files}. Current file: ${state.current_file || 'Waiting...'}`;
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
        const restorableCount = rows.filter((finding) => finding.type !== 'malware' && ['core_checksum', 'plugin_checksum', 'theme_checksum'].includes(finding.source)).length;

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
                ${restorableCount > 0 ? `<button type="button" class="button button-secondary firephage-restore-integrity-files">${firephageAdmin.labels.restoreAllFiles || 'Restore All Modified Files'}</button>` : ''}
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
                                <td><input type="checkbox" class="firephage-findings-select" value="${finding.file}" ${selectedFindings.has(finding.file) ? 'checked' : ''}></td>
                                <td><code>${finding.file}</code></td>
                                <td><span class="firephage-badge firephage-badge--${finding.type === 'malware' ? 'critical' : 'warning'}">${status}</span></td>
                                <td>${details.join(' | ')}</td>
                                <td>${finding.type === 'malware'
                                    ? `<div class="firephage-row-actions"><button type="button" class="button button-secondary firephage-preview-file" data-file="${finding.file}">${firephageAdmin.labels.previewFile}</button><button type="button" class="button firephage-button-danger firephage-delete-finding" data-file="${finding.file}">${firephageAdmin.labels.deleteFile}</button></div>`
                                    : `<div class="firephage-row-actions"><button type="button" class="button button-secondary firephage-preview-file" data-file="${finding.file}">${firephageAdmin.labels.previewFile}</button>${['core_checksum', 'plugin_checksum', 'theme_checksum'].includes(finding.source) ? `<details class="firephage-action-menu"><summary class="button button-secondary">${firephageAdmin.labels.moreActions || 'Actions'}</summary><div class="firephage-action-menu__panel"><button type="button" class="button button-secondary firephage-compare-file" data-file="${finding.file}" data-source="${finding.source}">${firephageAdmin.labels.compareFile || 'Compare'}</button><button type="button" class="button button-secondary firephage-restore-file" data-file="${finding.file}" data-source="${finding.source}">${firephageAdmin.labels.restoreFile || 'Restore'}</button></div></details>` : ''}</div>`}</td>
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
        const previousScanId = currentScanState && currentScanState.scan_id ? String(currentScanState.scan_id) : '';
        currentScanState = state;
        if (String(state.scan_id || '') !== previousScanId) {
            restoreWarningDismissedForScanId = '';
        }
        const badge = document.getElementById('firephage-scan-status-badge');
        const overviewBadge = document.getElementById('firephage-overview-scan-status-badge');
        const progressBar = document.getElementById('firephage-scan-progress-bar');
        const progressLabelNode = document.getElementById('firephage-scan-progress-label');
        const overviewSummary = document.getElementById('firephage-overview-scan-summary');
        const findings = document.getElementById('firephage-scan-findings');
        const scannerFlaggedStat = document.querySelector('.firephage-scanner-flagged-stat .firephage-stat-value');
        const scannerModifiedStat = document.querySelector('.firephage-scanner-modified-stat .firephage-stat-value');
        const overviewFlaggedStat = document.querySelector('.firephage-overview-flagged-stat .firephage-stat-value');
        const overviewModifiedStat = document.querySelector('.firephage-overview-modified-stat .firephage-stat-value');
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

        [scannerFlaggedStat, overviewFlaggedStat].forEach((node) => {
            if (node) {
                node.textContent = `${state.suspicious_files || 0}`;
            }
        });

        [scannerModifiedStat, overviewModifiedStat].forEach((node) => {
            if (node) {
                node.textContent = `${state.official_checksum_mismatches || 0}`;
            }
        });

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

    const renderHealth = (payload) => {
        const report = payload && payload.report ? payload.report : {};
        const healthChecks = document.getElementById('firephage-health-checks');
        const checksumNode = document.getElementById('firephage-core-checksum');
        const scoreBadge = document.getElementById('firephage-security-score-badge');
        const scoreValue = document.getElementById('firephage-security-score-value');
        const scoreSummary = document.getElementById('firephage-security-score-summary');
        const scoreHints = document.getElementById('firephage-security-score-hints');
        const overviewStatusBadge = document.getElementById('firephage-overview-status-badge');
        const overviewStatusSummary = document.getElementById('firephage-overview-status-summary');
        const overviewChecksValue = document.querySelector('.firephage-overview-checks-stat .firephage-stat-value');
        const overviewChecksSummary = document.querySelector('.firephage-overview-checks-stat .firephage-stat-description');
        const overviewProtectionValue = document.querySelector('.firephage-overview-protection-stat .firephage-stat-value');
        const overviewProtectionSummary = document.querySelector('.firephage-overview-protection-stat .firephage-stat-description');
        const overviewSyncValue = document.querySelector('.firephage-overview-sync-stat .firephage-stat-value');
        const overviewSyncSummary = document.querySelector('.firephage-overview-sync-stat .firephage-stat-description');

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

        if (payload && payload.security_score) {
            if (scoreBadge) {
                setBadge(scoreBadge, payload.security_score.label || 'Needs attention', payload.security_score.tone || 'critical');
            }

            if (scoreValue) {
                scoreValue.textContent = `${payload.security_score.score || 0}`;
            }

            if (scoreSummary) {
                scoreSummary.textContent = payload.security_score.summary || '';
            }

            if (scoreHints) {
                scoreHints.innerHTML = Array.isArray(payload.security_score.hints)
                    ? payload.security_score.hints.map((hint) => `<span class="firephage-score-hint">${hint}</span>`).join('')
                    : '';
            }
        }

        if (payload && payload.overview_status) {
            if (overviewStatusBadge) {
                setBadge(overviewStatusBadge, payload.overview_status.label || 'Needs review', payload.overview_status.tone || 'warning');
            }

            if (overviewStatusSummary) {
                overviewStatusSummary.textContent = payload.overview_status.summary || '';
            }

            if (overviewChecksValue) {
                overviewChecksValue.textContent = payload.overview_status.checks_value || '0 / 0';
            }

            if (overviewChecksSummary) {
                overviewChecksSummary.textContent = payload.overview_status.checks_summary || '';
            }

            if (overviewProtectionValue) {
                overviewProtectionValue.textContent = payload.overview_status.protection_value || '';
            }

            if (overviewProtectionSummary) {
                overviewProtectionSummary.textContent = payload.overview_status.protection_summary || '';
            }

            if (overviewSyncValue) {
                overviewSyncValue.textContent = payload.overview_status.sync_value || '';
            }

            if (overviewSyncSummary) {
                overviewSyncSummary.textContent = payload.overview_status.sync_summary || '';
            }
        }
    };

    const schedulePoll = () => {
        if (pollTimer) {
            window.clearTimeout(pollTimer);
        }

        pollTimer = window.setTimeout(() => {
            if (scanPollRequest && typeof scanPollRequest.abort === 'function') {
                scanPollRequest.abort();
            }

            scanPollRequest = request('firephage_process_scan_batch')
                .always(() => {
                    request('firephage_scan_status')
                        .done((response) => {
                            if (response.success) {
                                renderScanState(response.data.state);
                            }
                        });
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
            const nextTab = button.dataset.tab || 'overview';

            try {
                window.localStorage.setItem(tabStorageKey, nextTab);
            } catch (error) {
                // Ignore storage issues and keep tab switching working.
            }

            if (window.history && typeof window.history.replaceState === 'function') {
                window.history.replaceState(null, '', `#${nextTab}`);
            }

            setActiveTab(nextTab);
        });
    });

    let initialTab = app.dataset.activeTab || 'overview';
    const hashTab = window.location.hash ? window.location.hash.replace('#', '') : '';
    const knownTabs = new Set(tabButtons.map((button) => button.dataset.tab).filter(Boolean));

    if (hashTab && knownTabs.has(hashTab)) {
        initialTab = hashTab;
    } else {
        try {
            const storedTab = window.localStorage.getItem(tabStorageKey) || '';

            if (storedTab && knownTabs.has(storedTab)) {
                initialTab = storedTab;
            }
        } catch (error) {
            // Ignore storage issues and fall back to the default tab.
        }
    }

    setFirewallRuleTab(firewallRuleTabState);
    setActiveTab(initialTab);

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
                        renderHealth(response.data);
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

            ['notifications_webhook_url', 'notifications_slack_channel'].forEach((key) => {
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

    const continueSetupWizardFromToken = () => {
        if (!setupWizardForm) {
            return;
        }

        clearModalFeedback(setupWizardFeedback);

        const requestTokenInput = setupWizardForm.querySelector('input[name="request_free_token"]');
        const emailInput = setupWizardForm.querySelector('input[name="setup_token_email"]');
        const marketingInput = setupWizardForm.querySelector('input[name="setup_marketing_opt_in"]');
        const wantsToken = !!(requestTokenInput && requestTokenInput.checked);

        if (freeTokenState.status && freeTokenState.status !== 'pending') {
            setSetupWizardStep('settings');
            return;
        }

        if (!wantsToken) {
            setSetupWizardStep('settings');
            return;
        }

        if (!emailInput || !emailInput.value.trim()) {
            showModalFeedback(setupWizardFeedback, 'Enter an email address or turn off the free-token option to continue.', true);
            return;
        }

        if (setupWizardNextButton) {
            setupWizardNextButton.disabled = true;
            setupWizardNextButton.textContent = firephageAdmin.labels.registeringFreeToken;
        }

        request('firephage_register_free_token', {
            email: emailInput.value.trim(),
            marketing_opt_in: marketingInput && marketingInput.checked ? '1' : '',
        })
            .done((response) => {
                if (response.success) {
                    renderFreeTokenSummary(response.data.settings || null);
                    setSetupWizardStep('settings');
                } else {
                    showModalFeedback(setupWizardFeedback, (response.data && response.data.message) || 'Unable to request the free token.', true);
                }
            })
            .fail((xhr) => {
                showModalFeedback(setupWizardFeedback, (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to request the free token.', true);
            })
            .always(() => {
                if (setupWizardNextButton) {
                    setupWizardNextButton.disabled = false;
                    setupWizardNextButton.textContent = 'Next';
                }
            });
    };

    const completeSetupWizard = (mode = 'custom') => {
        if (!setupWizardForm) {
            return;
        }

        clearModalFeedback(setupWizardFeedback);

        const submitButton = setupWizardForm.querySelector('.firephage-save-setup-wizard');
        const frequencySelect = setupWizardForm.querySelector('select[name="malware_auto_scan_interval"]');
        const profileSelect = setupWizardForm.querySelector('select[name="bruteforce_profile"]');
        const checksumCacheInput = setupWizardForm.querySelector('input[name="use_firephage_checksum_cache"]');

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
            use_firephage_checksum_cache: checksumCacheInput && checksumCacheInput.checked ? '1' : '',
        })
            .done((response) => {
                if (response.success) {
                    setupWizardState.shouldOpen = false;

                    if (scannerSettingsForm && response.data.settings) {
                        const autoScanToggle = scannerSettingsForm.querySelector('input[name="malware_auto_scans_enabled"]');
                        const checksumCacheToggle = scannerSettingsForm.querySelector('input[name="use_firephage_checksum_cache"]');
                        const scanInterval = scannerSettingsForm.querySelector('select[name="malware_auto_scan_interval"]');
                        const scannerAutoScanStatus = document.getElementById('firephage-scanner-auto-scan');

                        if (autoScanToggle) {
                            autoScanToggle.checked = response.data.settings.malware_auto_scans_enabled === '1';
                        }

                        if (scanInterval) {
                            scanInterval.value = response.data.settings.malware_auto_scan_interval || 'twice_daily';
                        }

                        if (checksumCacheToggle) {
                            checksumCacheToggle.checked = response.data.settings.use_firephage_checksum_cache === '1';
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
            const checksumCacheInput = setupWizardForm.querySelector('input[name="use_firephage_checksum_cache"]');

            if (frequencySelect) {
                frequencySelect.value = 'twice_daily';
            }

            if (profileSelect) {
                profileSelect.value = 'recommended';
            }

            if (checksumCacheInput) {
                checksumCacheInput.checked = true;
            }

            completeSetupWizard('recommended');
        });
    }

    if (setupWizardNextButton) {
        setupWizardNextButton.addEventListener('click', () => {
            continueSetupWizardFromToken();
        });
    }

    if (setupWizardBackButton) {
        setupWizardBackButton.addEventListener('click', () => {
            clearModalFeedback(setupWizardFeedback);
            setSetupWizardStep('token');
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
        const connectSubmitButton = connectForm.querySelector('.firephage-connect-submit');
        const tokenInput = connectForm.querySelector('input[name="connection_token"]');
        const dashboardInput = connectForm.querySelector('input[name="dashboard_url"]');

        const setConnectFormConnectedState = (connected) => {
            if (tokenInput) {
                tokenInput.disabled = connected;
                if (connected) {
                    tokenInput.value = '';
                }
            }

            if (dashboardInput) {
                dashboardInput.disabled = connected;
            }

            if (connectSubmitButton) {
                connectSubmitButton.disabled = connected;
            }

            connectForm.dataset.connected = connected ? '1' : '0';
        };

        setConnectFormConnectedState(connectForm.dataset.connected === '1');

        connectForm.addEventListener('submit', (event) => {
            event.preventDefault();

            if (connectForm.dataset.connected === '1') {
                return;
            }

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

                    setConnectFormConnectedState(true);

                    proTabState.firewallLoaded = false;
                    proTabState.performanceLoaded = false;
                    proTabState.statusLoaded = false;
                    maybeLoadProTab('notifications');
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

                    setConnectFormConnectedState(false);
                    proTabState.firewallLoaded = false;
                    proTabState.performanceLoaded = false;
                    proTabState.statusLoaded = false;
                    showToast(response.data.message || 'Plugin disconnected.');
                })
                .fail(() => {
                    showToast('Unable to disconnect the plugin.', true);
                });
        });
    }

    app.addEventListener('change', (event) => {
        if (event.target instanceof HTMLSelectElement && event.target.id === 'firephage-firewall-range') {
            firewallRangeState = event.target.value === '7d' ? '7d' : '24h';
            refreshFirewallSummary();
            return;
        }

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

        const bruteforceViewButton = target.closest('[data-bruteforce-view]');

        if (bruteforceViewButton instanceof HTMLElement) {
            const nextView = bruteforceViewButton.dataset.bruteforceView || 'active';
            const allButtons = Array.from(app.querySelectorAll('[data-bruteforce-view]'));
            const allPanels = Array.from(app.querySelectorAll('[data-bruteforce-panel]'));

            allButtons.forEach((button) => {
                button.classList.toggle('is-active', button === bruteforceViewButton);
                button.setAttribute('aria-pressed', button === bruteforceViewButton ? 'true' : 'false');
            });

            allPanels.forEach((panel) => {
                panel.hidden = panel.dataset.bruteforcePanel !== nextView;
            });

            return;
        }

        const firewallRuleTabButton = target.closest('[data-firewall-rule-tab]');

        if (firewallRuleTabButton instanceof HTMLElement) {
            setFirewallRuleTab(firewallRuleTabButton.dataset.firewallRuleTab || 'ip');
            return;
        }

        if (target.id === 'firephage-firewall-block-ip-button') {
            const ip = (firewallBlockIpInput && firewallBlockIpInput.value || '').trim();

            if (!ip) {
                showToast('Enter an IP address to block.', true);
                return;
            }

            target.setAttribute('disabled', 'disabled');
            request('firephage_create_firewall_rule', {
                rule_type: 'ip',
                target: ip,
            })
                .done((response) => {
                    if (response.success) {
                        if (firewallBlockIpInput) {
                            firewallBlockIpInput.value = '';
                        }
                        if (response.data && response.data.summary) {
                            renderFirewallSummary(response.data.summary);
                            setFirewallRuleTab('ip');
                        } else {
                            refreshFirewallSummary();
                        }
                        showToast((response.data && response.data.message) || 'Firewall rule created.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to create the firewall rule.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to create the firewall rule.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.id === 'firephage-firewall-allow-ip-button') {
            const ip = (firewallAllowIpInput && firewallAllowIpInput.value || '').trim();

            if (!ip) {
                showToast('Enter an IP address to allow.', true);
                return;
            }

            target.setAttribute('disabled', 'disabled');
            request('firephage_create_firewall_rule', {
                rule_type: 'ip',
                action: 'allow',
                target: ip,
            })
                .done((response) => {
                    if (response.success) {
                        if (firewallAllowIpInput) {
                            firewallAllowIpInput.value = '';
                        }
                        if (response.data && response.data.summary) {
                            renderFirewallSummary(response.data.summary);
                            setFirewallRuleTab('country');
                        } else {
                            refreshFirewallSummary();
                        }
                        showToast((response.data && response.data.message) || 'Allowlist rule created.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to create the allowlist rule.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to create the allowlist rule.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.id === 'firephage-firewall-block-country-button') {
            const code = firewallBlockCountrySelect
                ? normalizeFirewallOptionInput(firewallBlockCountrySelect.value, firewallCountryOptionMap)
                : '';

            if (!code) {
                showToast('Select a country to block.', true);
                return;
            }

            target.setAttribute('disabled', 'disabled');
            request('firephage_create_firewall_rule', {
                rule_type: 'country',
                target: code,
            })
                .done((response) => {
                    if (response.success) {
                        if (firewallBlockCountrySelect) {
                            firewallBlockCountrySelect.value = '';
                            if (firewallCountryChoices) {
                                firewallCountryChoices.removeActiveItems();
                                firewallCountryChoices.hideDropdown();
                            }
                        }
                        if (response.data && response.data.summary) {
                            renderFirewallSummary(response.data.summary);
                            setFirewallRuleTab('country');
                        } else {
                            refreshFirewallSummary();
                        }
                        showToast((response.data && response.data.message) || 'Country block created.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to create the country block.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to create the country block.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.id === 'firephage-firewall-block-continent-button') {
            const code = firewallBlockContinentSelect
                ? normalizeFirewallOptionInput(firewallBlockContinentSelect.value, firewallContinentOptionMap)
                : '';

            if (!code) {
                showToast('Select a continent to block.', true);
                return;
            }

            target.setAttribute('disabled', 'disabled');
            request('firephage_create_firewall_rule', {
                rule_type: 'continent',
                target: code,
            })
                .done((response) => {
                    if (response.success) {
                        if (firewallBlockContinentSelect) {
                            firewallBlockContinentSelect.value = '';
                            if (firewallContinentChoices) {
                                firewallContinentChoices.removeActiveItems();
                                firewallContinentChoices.hideDropdown();
                            }
                        }
                        if (response.data && response.data.summary) {
                            renderFirewallSummary(response.data.summary);
                        } else {
                            refreshFirewallSummary();
                        }
                        showToast((response.data && response.data.message) || 'Continent block created.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to create the continent block.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to create the continent block.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.id === 'firephage-performance-purge-cache') {
            target.setAttribute('disabled', 'disabled');
            request('firephage_purge_edge_cache')
                .done((response) => {
                    if (response.success) {
                        showToast((response.data && response.data.message) || 'Edge cache purge requested.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to purge edge cache.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to purge edge cache.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.id === 'firephage-performance-toggle-troubleshooting') {
            const enable = !(latestPerformancePayload && latestPerformancePayload.settings && latestPerformancePayload.settings.troubleshooting_mode);
            target.setAttribute('disabled', 'disabled');
            request('firephage_toggle_troubleshooting_mode', {
                enabled: enable ? '1' : '',
            })
                .done((response) => {
                    if (response.success) {
                        if (response.data && response.data.summary) {
                            renderPerformanceSummary(response.data.summary);
                        } else {
                            refreshPerformanceSummary();
                        }
                        refreshFirewallSummary();
                        showToast((response.data && response.data.message) || 'Troubleshooting mode updated.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to update troubleshooting mode.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to update troubleshooting mode.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.classList.contains('firephage-remove-firewall-rule')) {
            const ruleId = target.dataset.ruleId || '';
            const ruleTarget = target.dataset.ruleTarget || '';
            const targetCode = target.dataset.targetCode || '';
            if (!ruleId) {
                showToast('Missing firewall rule id.', true);
                return;
            }

            openConfirmModal({
                title: firephageAdmin.labels.confirmDeleteFirewallRuleTitle || 'Delete Firewall Rule?',
                body: `<p>${escapeHtml(firephageAdmin.labels.confirmDeleteFirewallRuleBody || 'This will remove the selected access rule from FirePhage and WordPress.')}</p><p><strong>${escapeHtml(firephageAdmin.labels.confirmDeleteFirewallRuleTargetLabel || 'Rule target')}:</strong></p><div class="firephage-confirm-files"><code>${escapeHtml(ruleTarget || ruleId)}</code></div>`,
                actionLabel: firephageAdmin.labels.confirmDeleteFirewallRuleAction || firephageAdmin.labels.confirmAction || 'Delete',
                onConfirm: () => {
                    target.setAttribute('disabled', 'disabled');
                    request('firephage_delete_firewall_rule', {
                        rule_id: ruleId,
                        target: targetCode,
                    })
                        .done((response) => {
                            if (response.success) {
                                if (response.data && response.data.summary) {
                                    renderFirewallSummary(response.data.summary);
                                } else {
                                    refreshFirewallSummary();
                                }
                                showToast((response.data && response.data.message) || 'Firewall rule removed.');
                            } else {
                                showToast((response.data && response.data.message) || 'Unable to remove the firewall rule.', true);
                            }
                        })
                        .fail((xhr) => {
                            showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to remove the firewall rule.', true);
                        })
                        .always(() => {
                            target.removeAttribute('disabled');
                            closeConfirmModal();
                        });
                },
            });
            return;
        }

        if (target.classList.contains('firephage-toggle-firewall-rule')) {
            const ruleId = target.dataset.ruleId || '';
            const enabled = target.dataset.ruleEnabled || '';

            if (!ruleId) {
                showToast('Missing firewall rule id.', true);
                return;
            }

            target.setAttribute('disabled', 'disabled');
            request('firephage_toggle_firewall_rule', {
                rule_id: ruleId,
                enabled,
            })
                .done((response) => {
                    if (response.success) {
                        if (response.data && response.data.summary) {
                            renderFirewallSummary(response.data.summary);
                        } else {
                            refreshFirewallSummary();
                        }
                        showToast((response.data && response.data.message) || 'Firewall rule updated.');
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to update the firewall rule.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to update the firewall rule.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
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

        if (target.classList.contains('firephage-compare-file')) {
            target.setAttribute('disabled', 'disabled');

            request('firephage_compare_file', {
                file: target.dataset.file || '',
                source: target.dataset.source || '',
            })
                .done((response) => {
                    if (response.success) {
                        openCompareModal(response.data.compare || response.data);
                    } else {
                        showToast((response.data && response.data.message) || 'Unable to compare the file.', true);
                    }
                })
                .fail((xhr) => {
                    showToast((xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) || 'Unable to compare the file.', true);
                })
                .always(() => {
                    target.removeAttribute('disabled');
                });
            return;
        }

        if (target.classList.contains('firephage-restore-integrity-files')) {
            const count = (currentScanState.findings || []).filter((finding) => finding.type !== 'malware' && ['core_checksum', 'plugin_checksum', 'theme_checksum'].includes(finding.source)).length;
            confirmRestoreAction({
                title: firephageAdmin.labels.confirmRestoreAllTitle || 'Restore All Modified Files?',
                body: firephageAdmin.labels.confirmRestoreAllBody || 'This will overwrite every checksum-based modified file in the current findings list with the official WordPress.org package version.',
                button: target,
                fileCount: count,
                onConfirm: restoreAllIntegrityFiles,
            });
            return;
        }

        if (target.classList.contains('firephage-restore-file')) {
            confirmRestoreAction({
                title: firephageAdmin.labels.confirmRestoreTitle || 'Restore Official File?',
                body: firephageAdmin.labels.confirmRestoreBody || 'This will overwrite the local file with the official WordPress.org version for the installed package release.',
                button: target,
                fileCount: 1,
                onConfirm: restoreSingleIntegrityFile,
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
                dismissSetupWizard();
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

    maybeLoadProTab('notifications');

    renderFreeTokenSummary();

    if (setupWizardState.shouldOpen) {
        openSetupWizardModal();
    } else if (freeTokenState.requiresDecision) {
        openFreeTokenModal();
    }
}(jQuery));
