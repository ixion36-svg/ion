/**
 * Integration Wizard - AI-Assisted Setup for ION
 *
 * Provides a step-by-step configuration wizard for all integrations
 * with AI-powered error diagnosis using Ollama.
 */

// =============================================================================
// Wizard State Management
// =============================================================================

const WIZARD_STORAGE_KEY = 'ion_wizard_state';
const WIZARD_EXPIRY_HOURS = 24;

let wizardState = {
    currentStep: 'welcome',  // welcome, select, configure, summary
    selectedIntegrations: [],
    currentIntegrationIndex: 0,
    currentSubStep: 0,  // 0=basic, 1=auth, 2=advanced, 3=test
    configs: {},  // integration_name -> config values
    testResults: {},  // integration_name -> test result
    integrationMeta: {},  // metadata about each integration
};

let wizardModal = null;
let ollamaModelsCache = null;

/**
 * Initialize wizard state from localStorage if available
 */
function loadWizardState() {
    try {
        const saved = localStorage.getItem(WIZARD_STORAGE_KEY);
        if (saved) {
            const parsed = JSON.parse(saved);
            // Check expiry
            if (parsed.savedAt && Date.now() - parsed.savedAt < WIZARD_EXPIRY_HOURS * 60 * 60 * 1000) {
                wizardState = { ...wizardState, ...parsed.state };
                return true;
            } else {
                localStorage.removeItem(WIZARD_STORAGE_KEY);
            }
        }
    } catch (e) {
        console.error('Failed to load wizard state:', e);
    }
    return false;
}

/**
 * Save wizard state to localStorage
 */
function saveWizardState() {
    try {
        localStorage.setItem(WIZARD_STORAGE_KEY, JSON.stringify({
            savedAt: Date.now(),
            state: wizardState,
        }));
    } catch (e) {
        console.error('Failed to save wizard state:', e);
    }
}

/**
 * Clear wizard state
 */
function clearWizardState() {
    wizardState = {
        currentStep: 'welcome',
        selectedIntegrations: [],
        currentIntegrationIndex: 0,
        currentSubStep: 0,
        configs: {},
        testResults: {},
        integrationMeta: {},
    };
    localStorage.removeItem(WIZARD_STORAGE_KEY);
}

// =============================================================================
// Wizard UI Components
// =============================================================================

/**
 * Open the integration wizard modal
 */
async function openIntegrationWizard() {
    // Load available integrations first
    const integrationsData = await fetchIntegrations();
    if (!integrationsData) return;

    wizardState.integrationMeta = integrationsData.integrations;

    // Check for saved state
    const hasResumedState = loadWizardState();

    // Create and show modal
    wizardModal = createWizardModal();
    document.body.appendChild(wizardModal);

    if (hasResumedState && wizardState.currentStep !== 'welcome') {
        // Ask user if they want to resume
        renderResumePrompt();
    } else {
        renderCurrentStep();
    }
}

/**
 * Close the wizard modal
 */
function closeWizard() {
    if (wizardModal) {
        wizardModal.remove();
        wizardModal = null;
    }
}

/**
 * Create the wizard modal structure
 */
function createWizardModal() {
    const modal = document.createElement('div');
    modal.className = 'wizard-modal-overlay';
    modal.id = 'integration-wizard-modal';
    modal.innerHTML = `
        <div class="wizard-modal">
            <div class="wizard-header">
                <h2>Integration Wizard</h2>
                <button class="wizard-close" onclick="closeWizard()">&times;</button>
            </div>
            <div class="wizard-progress" id="wizard-progress">
                <div class="wizard-progress-step active" data-step="welcome">Welcome</div>
                <div class="wizard-progress-step" data-step="select">Select</div>
                <div class="wizard-progress-step" data-step="configure">Configure</div>
                <div class="wizard-progress-step" data-step="summary">Summary</div>
            </div>
            <div class="wizard-content" id="wizard-content">
                <!-- Dynamic content rendered here -->
            </div>
            <div class="wizard-footer" id="wizard-footer">
                <!-- Dynamic buttons rendered here -->
            </div>
        </div>
    `;
    return modal;
}

/**
 * Update progress indicator
 */
function updateProgress() {
    const steps = ['welcome', 'select', 'configure', 'summary'];
    const currentIndex = steps.indexOf(wizardState.currentStep);

    document.querySelectorAll('.wizard-progress-step').forEach((el, idx) => {
        el.classList.remove('active', 'completed');
        if (idx < currentIndex) {
            el.classList.add('completed');
        } else if (idx === currentIndex) {
            el.classList.add('active');
        }
    });
}

/**
 * Render the current step
 */
function renderCurrentStep() {
    updateProgress();

    switch (wizardState.currentStep) {
        case 'welcome':
            renderWelcomeStep();
            break;
        case 'select':
            renderSelectStep();
            break;
        case 'configure':
            renderConfigureStep();
            break;
        case 'summary':
            renderSummaryStep();
            break;
    }
}

// =============================================================================
// Step Renderers
// =============================================================================

/**
 * Render the resume prompt
 */
function renderResumePrompt() {
    const content = document.getElementById('wizard-content');
    const footer = document.getElementById('wizard-footer');

    const selectedCount = wizardState.selectedIntegrations.length;
    const configuredCount = Object.keys(wizardState.configs).length;

    content.innerHTML = `
        <div class="wizard-resume">
            <h3>Resume Previous Setup?</h3>
            <p>We found an incomplete wizard session:</p>
            <ul>
                <li><strong>${selectedCount}</strong> integrations selected</li>
                <li><strong>${configuredCount}</strong> partially configured</li>
                <li>Current step: <strong>${wizardState.currentStep}</strong></li>
            </ul>
            <p>Would you like to continue where you left off?</p>
        </div>
    `;

    footer.innerHTML = `
        <button class="btn btn-secondary" onclick="startFresh()">Start Fresh</button>
        <button class="btn btn-primary" onclick="renderCurrentStep()">Continue</button>
    `;
}

/**
 * Start fresh wizard
 */
function startFresh() {
    clearWizardState();
    renderCurrentStep();
}

/**
 * Render welcome step
 */
function renderWelcomeStep() {
    const content = document.getElementById('wizard-content');
    const footer = document.getElementById('wizard-footer');

    // Count configured integrations
    let configuredCount = 0;
    let totalCount = 0;
    for (const [name, meta] of Object.entries(wizardState.integrationMeta)) {
        totalCount++;
        if (meta.configured) configuredCount++;
    }

    content.innerHTML = `
        <div class="wizard-welcome">
            <div class="wizard-welcome-icon">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
            </div>
            <h3>Welcome to the Integration Wizard</h3>
            <p>This wizard will help you configure your integrations step-by-step with AI-assisted troubleshooting.</p>

            <div class="wizard-status-overview">
                <div class="status-card">
                    <div class="status-value">${configuredCount}</div>
                    <div class="status-label">Configured</div>
                </div>
                <div class="status-card">
                    <div class="status-value">${totalCount - configuredCount}</div>
                    <div class="status-label">Not Configured</div>
                </div>
                <div class="status-card">
                    <div class="status-value">${totalCount}</div>
                    <div class="status-label">Total</div>
                </div>
            </div>

            <div class="wizard-features">
                <div class="feature-item">
                    <span class="feature-icon">&#10003;</span>
                    <span>Step-by-step configuration</span>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">&#10003;</span>
                    <span>Connection testing</span>
                </div>
                <div class="feature-item">
                    <span class="feature-icon">&#10003;</span>
                    <span>AI-powered error diagnosis</span>
                </div>
            </div>
        </div>
    `;

    footer.innerHTML = `
        <button class="btn btn-secondary" onclick="closeWizard()">Cancel</button>
        <button class="btn btn-primary" onclick="goToStep('select')">Get Started</button>
    `;
}

/**
 * Render integration selection step
 */
function renderSelectStep() {
    const content = document.getElementById('wizard-content');
    const footer = document.getElementById('wizard-footer');

    let integrationsHtml = '';
    for (const [name, meta] of Object.entries(wizardState.integrationMeta)) {
        const isSelected = wizardState.selectedIntegrations.includes(name);
        const isConfigured = meta.configured;

        integrationsHtml += `
            <div class="integration-select-card ${isSelected ? 'selected' : ''}" onclick="toggleIntegration('${name}')">
                <div class="integration-checkbox">
                    <input type="checkbox" ${isSelected ? 'checked' : ''} onclick="event.stopPropagation(); toggleIntegration('${name}')">
                </div>
                <div class="integration-info">
                    <div class="integration-name">${escapeHtml(meta.name)}</div>
                    <div class="integration-desc">${escapeHtml(meta.description)}</div>
                </div>
                <div class="integration-status">
                    ${isConfigured
                        ? '<span class="status-badge configured">Configured</span>'
                        : '<span class="status-badge not-configured">Not Configured</span>'}
                </div>
            </div>
        `;
    }

    content.innerHTML = `
        <div class="wizard-select">
            <h3>Select Integrations to Configure</h3>
            <p>Choose the integrations you want to set up. You can configure them one by one.</p>

            <div class="integration-list">
                ${integrationsHtml}
            </div>

            <div class="quick-actions">
                <button class="btn btn-sm" onclick="selectAllIntegrations()">Select All</button>
                <button class="btn btn-sm" onclick="selectUnconfigured()">Select Unconfigured</button>
                <button class="btn btn-sm" onclick="clearSelection()">Clear Selection</button>
            </div>
        </div>
    `;

    const canProceed = wizardState.selectedIntegrations.length > 0;
    footer.innerHTML = `
        <button class="btn btn-secondary" onclick="goToStep('welcome')">Back</button>
        <button class="btn btn-primary" onclick="goToStep('configure')" ${canProceed ? '' : 'disabled'}>
            Configure (${wizardState.selectedIntegrations.length})
        </button>
    `;
}

/**
 * Toggle integration selection
 */
function toggleIntegration(name) {
    const idx = wizardState.selectedIntegrations.indexOf(name);
    if (idx >= 0) {
        wizardState.selectedIntegrations.splice(idx, 1);
    } else {
        wizardState.selectedIntegrations.push(name);
    }
    saveWizardState();
    renderSelectStep();
}

function selectAllIntegrations() {
    wizardState.selectedIntegrations = Object.keys(wizardState.integrationMeta);
    saveWizardState();
    renderSelectStep();
}

function selectUnconfigured() {
    wizardState.selectedIntegrations = Object.entries(wizardState.integrationMeta)
        .filter(([name, meta]) => !meta.configured)
        .map(([name, meta]) => name);
    saveWizardState();
    renderSelectStep();
}

function clearSelection() {
    wizardState.selectedIntegrations = [];
    saveWizardState();
    renderSelectStep();
}

/**
 * Render the configure step (main configuration flow)
 */
function renderConfigureStep() {
    const content = document.getElementById('wizard-content');
    const footer = document.getElementById('wizard-footer');

    if (wizardState.selectedIntegrations.length === 0) {
        goToStep('select');
        return;
    }

    const currentIntegration = wizardState.selectedIntegrations[wizardState.currentIntegrationIndex];
    const meta = wizardState.integrationMeta[currentIntegration];
    const config = wizardState.configs[currentIntegration] || {};
    const subSteps = getSubSteps(currentIntegration);
    const currentSubStepInfo = subSteps[wizardState.currentSubStep];

    // Build sub-step indicator
    let subStepIndicator = '<div class="wizard-substeps">';
    subSteps.forEach((step, idx) => {
        let stepClass = '';
        if (idx < wizardState.currentSubStep) stepClass = 'completed';
        else if (idx === wizardState.currentSubStep) stepClass = 'active';
        subStepIndicator += `<div class="substep ${stepClass}">${step.name}</div>`;
    });
    subStepIndicator += '</div>';

    // Build integration indicator
    let integrationIndicator = `
        <div class="wizard-integration-header">
            <span class="integration-counter">${wizardState.currentIntegrationIndex + 1} of ${wizardState.selectedIntegrations.length}</span>
            <h3>${escapeHtml(meta.name)}</h3>
            <p>${escapeHtml(meta.description)}</p>
        </div>
    `;

    // Build form content based on sub-step
    let formContent = renderSubStepContent(currentIntegration, currentSubStepInfo, config);

    content.innerHTML = `
        <div class="wizard-configure">
            ${integrationIndicator}
            ${subStepIndicator}
            <div class="wizard-form-container">
                ${formContent}
            </div>
            <div id="wizard-diagnosis-panel" class="diagnosis-panel" style="display: none;"></div>
        </div>
    `;

    // Footer buttons
    const isFirstIntegration = wizardState.currentIntegrationIndex === 0;
    const isLastIntegration = wizardState.currentIntegrationIndex === wizardState.selectedIntegrations.length - 1;
    const isFirstSubStep = wizardState.currentSubStep === 0;
    const isLastSubStep = wizardState.currentSubStep === subSteps.length - 1;

    let backAction = isFirstSubStep
        ? (isFirstIntegration ? 'goToStepSelect' : 'previousIntegration')
        : 'previousSubStep';

    let nextAction = isLastSubStep
        ? (isLastIntegration ? 'goToStepSummary' : 'nextIntegration')
        : 'nextSubStep';

    let nextLabel = isLastSubStep
        ? (isLastIntegration ? 'Review & Save' : 'Next Integration')
        : 'Next';

    footer.innerHTML = `
        <button class="btn btn-secondary" onclick="wizardDispatch('${backAction}')">Back</button>
        <div class="footer-spacer"></div>
        <button class="btn" onclick="skipIntegration()" style="margin-right: auto;">Skip This Integration</button>
        <button class="btn btn-primary" onclick="saveSubStepAndContinue('${nextAction}')">${nextLabel}</button>
    `;
}

/**
 * Get sub-steps for an integration
 */
function getSubSteps(integrationName) {
    const meta = wizardState.integrationMeta[integrationName];
    const fields = meta.fields || {};

    const steps = [];

    // Basic config (URL, etc.)
    const urlField = fields.url;
    if (urlField) {
        steps.push({ name: 'Basic', type: 'basic', fields: ['url'] });
    }

    // Authentication
    const hasAuth = fields.token || fields.api_key || fields.username || fields.password;
    if (hasAuth) {
        const authFields = [];
        if (fields.token) authFields.push('token');
        if (fields.api_key) authFields.push('api_key');
        if (fields.username) authFields.push('username');
        if (fields.password) authFields.push('password');
        steps.push({ name: 'Authentication', type: 'auth', fields: authFields });
    }

    // Advanced options
    const advancedFields = Object.keys(fields).filter(f =>
        !['url', 'token', 'api_key', 'username', 'password'].includes(f)
    );
    if (advancedFields.length > 0) {
        steps.push({ name: 'Advanced', type: 'advanced', fields: advancedFields });
    }

    // Test connection
    steps.push({ name: 'Test', type: 'test', fields: [] });

    return steps;
}

/**
 * Render content for a sub-step
 */
function renderSubStepContent(integrationName, subStep, config) {
    const meta = wizardState.integrationMeta[integrationName];
    const fields = meta.fields || {};

    if (subStep.type === 'test') {
        return renderTestStep(integrationName);
    }

    let html = '<div class="wizard-form">';

    for (const fieldName of subStep.fields) {
        const field = fields[fieldName];
        if (!field) continue;

        const value = config[fieldName] !== undefined ? config[fieldName] : (field.default || '');
        const required = field.required ? 'required' : '';

        html += `<div class="form-group">`;
        html += `<label for="wizard-${fieldName}">${escapeHtml(field.label)}${field.required ? ' *' : ''}</label>`;

        if (field.type === 'checkbox') {
            const checked = value === true || value === 'true' || value === field.default;
            html += `
                <label class="checkbox-label">
                    <input type="checkbox" id="wizard-${fieldName}" name="${fieldName}" ${checked ? 'checked' : ''}>
                    ${escapeHtml(field.label)}
                </label>
            `;
        } else if (field.type === 'select') {
            let options = field.options || [];

            // For Ollama model, try to load dynamically
            if (fieldName === 'model' && field.dynamic) {
                options = ollamaModelsCache || [field.default];
            }

            html += `<select id="wizard-${fieldName}" name="${fieldName}" ${required}>`;
            for (const opt of options) {
                const optValue = typeof opt === 'object' ? opt.name : opt;
                const selected = value === optValue ? 'selected' : '';
                html += `<option value="${escapeHtml(optValue)}" ${selected}>${escapeHtml(optValue)}</option>`;
            }
            html += `</select>`;
        } else if (field.type === 'number') {
            html += `
                <input type="number" id="wizard-${fieldName}" name="${fieldName}"
                    value="${escapeHtml(String(value))}"
                    ${field.min !== undefined ? `min="${field.min}"` : ''}
                    ${field.max !== undefined ? `max="${field.max}"` : ''}
                    ${required}>
            `;
        } else {
            html += `
                <input type="${field.type}" id="wizard-${fieldName}" name="${fieldName}"
                    placeholder="${escapeHtml(field.placeholder || '')}"
                    value="${field.type === 'password' ? '' : escapeHtml(String(value))}"
                    ${required}>
            `;
            if (field.type === 'password' && config[fieldName]) {
                html += `<span class="form-help status-set">Currently set</span>`;
            }
        }

        if (field.type !== 'checkbox' && field.placeholder) {
            // html += `<span class="form-help">${escapeHtml(field.placeholder)}</span>`;
        }

        html += `</div>`;
    }

    html += '</div>';
    return html;
}

/**
 * Render test connection step
 */
function renderTestStep(integrationName) {
    const testResult = wizardState.testResults[integrationName];

    let statusHtml = '';
    if (testResult === undefined) {
        statusHtml = `
            <div class="test-status pending">
                <p>Click the button below to test your connection.</p>
            </div>
        `;
    } else if (testResult.success) {
        let detailsHtml = '';
        if (testResult.details) {
            detailsHtml = '<div class="test-details"><ul>';
            for (const [key, value] of Object.entries(testResult.details)) {
                if (value !== null && value !== undefined) {
                    detailsHtml += `<li><strong>${escapeHtml(key)}:</strong> ${escapeHtml(String(value))}</li>`;
                }
            }
            detailsHtml += '</ul></div>';
        }
        statusHtml = `
            <div class="test-status success">
                <div class="test-icon">&#10003;</div>
                <h4>Connection Successful!</h4>
                ${detailsHtml}
            </div>
        `;
    } else {
        // Escape the error for both HTML and the inline JS string literal:
        // backslash MUST be escaped first, otherwise the subsequent single-quote
        // escapes can be neutralised by an attacker-controlled trailing backslash.
        const errorJsLiteral = escapeHtml(testResult.error)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'");
        statusHtml = `
            <div class="test-status error">
                <div class="test-icon">&#10007;</div>
                <h4>Connection Failed</h4>
                <p class="error-message">${escapeHtml(testResult.error)}</p>
                <button class="btn btn-secondary" onclick="requestAIDiagnosis('${integrationName}', '${errorJsLiteral}')">
                    Get AI Diagnosis
                </button>
            </div>
        `;
    }

    return `
        <div class="wizard-test">
            <h4>Test Connection</h4>
            <p>Verify that your configuration is correct by testing the connection.</p>

            ${statusHtml}

            <div class="test-actions">
                <button class="btn btn-primary" onclick="testWizardConnection('${integrationName}')" id="test-connection-btn">
                    Test Connection
                </button>
            </div>
        </div>
    `;
}

/**
 * Test wizard connection
 */
async function testWizardConnection(integrationName) {
    const btn = document.getElementById('test-connection-btn');
    btn.disabled = true;
    btn.innerHTML = 'Testing...';

    // Gather current config
    collectCurrentFormData(integrationName);
    const config = wizardState.configs[integrationName] || {};

    try {
        const response = await fetch(`/api/admin/wizard/test/${integrationName}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(config),
        });

        const result = await response.json();
        wizardState.testResults[integrationName] = result;
        saveWizardState();

    } catch (error) {
        wizardState.testResults[integrationName] = {
            success: false,
            error: error.message,
        };
    }

    renderConfigureStep();
}

/**
 * Request AI diagnosis for a failed connection
 */
async function requestAIDiagnosis(integrationName, errorMessage) {
    const panel = document.getElementById('wizard-diagnosis-panel');
    panel.style.display = 'block';
    panel.innerHTML = `
        <div class="diagnosis-loading">
            <div class="spinner"></div>
            <p>Analyzing error with AI...</p>
        </div>
    `;

    // Prepare sanitized config
    const config = wizardState.configs[integrationName] || {};
    const sanitizedConfig = {};
    for (const [key, value] of Object.entries(config)) {
        if (['password', 'token', 'api_key', 'secret'].some(s => key.toLowerCase().includes(s))) {
            sanitizedConfig[key] = value ? '***SET***' : '(not set)';
        } else {
            sanitizedConfig[key] = value;
        }
    }

    try {
        const response = await fetch('/api/admin/wizard/diagnose', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                integration: integrationName,
                error_message: errorMessage,
                config: sanitizedConfig,
            }),
        });

        const result = await response.json();

        if (!result.available) {
            panel.innerHTML = `
                <div class="diagnosis-unavailable">
                    <p>${escapeHtml(result.message || 'AI diagnosis is not available')}</p>
                    <button class="btn btn-sm" onclick="hideDiagnosisPanel()">Close</button>
                </div>
            `;
            return;
        }

        renderDiagnosisPanel(integrationName, result.diagnosis);

    } catch (error) {
        panel.innerHTML = `
            <div class="diagnosis-error">
                <p>Failed to get AI diagnosis: ${escapeHtml(error.message)}</p>
                <button class="btn btn-sm" onclick="hideDiagnosisPanel()">Close</button>
            </div>
        `;
    }
}

/**
 * Render AI diagnosis panel
 */
function renderDiagnosisPanel(integrationName, diagnosis) {
    const panel = document.getElementById('wizard-diagnosis-panel');

    let solutionsHtml = '';
    if (diagnosis.solutions && diagnosis.solutions.length > 0) {
        solutionsHtml = '<div class="diagnosis-solutions"><h5>Suggested Fixes:</h5><ul>';
        diagnosis.solutions.forEach((solution, idx) => {
            solutionsHtml += `<li>${escapeHtml(solution)}</li>`;
        });
        solutionsHtml += '</ul></div>';
    }

    let actionableHtml = '';
    if (diagnosis.actionable && diagnosis.actionable.length > 0) {
        actionableHtml = '<div class="diagnosis-actionable"><h5>Quick Fixes:</h5>';
        diagnosis.actionable.forEach(action => {
            let label = action;
            let handler = '';
            if (action === 'disable_ssl_verification') {
                label = 'Disable SSL Verification';
                handler = `applyQuickFix('${integrationName}', 'verify_ssl', false)`;
            } else if (action === 'increase_timeout') {
                label = 'Increase Timeout to 300s';
                handler = `applyQuickFix('${integrationName}', 'timeout', 300)`;
            } else if (action === 'use_http') {
                label = 'Switch to HTTP';
                handler = `applyHttpFix('${integrationName}')`;
            }
            if (handler) {
                actionableHtml += `<button class="btn btn-sm btn-warning" onclick="${handler}">${escapeHtml(label)}</button> `;
            }
        });
        actionableHtml += '</div>';
    }

    let securityHtml = '';
    if (diagnosis.security_note) {
        securityHtml = `
            <div class="diagnosis-security">
                <strong>Security Note:</strong> ${escapeHtml(diagnosis.security_note)}
            </div>
        `;
    }

    panel.innerHTML = `
        <div class="diagnosis-content">
            <div class="diagnosis-header">
                <h4>AI Diagnosis</h4>
                <button class="btn-close" onclick="hideDiagnosisPanel()">&times;</button>
            </div>

            <div class="diagnosis-summary">
                <strong>Diagnosis:</strong> ${escapeHtml(diagnosis.summary || 'Unknown error')}
            </div>

            ${diagnosis.cause ? `
                <div class="diagnosis-cause">
                    <strong>Likely Cause:</strong> ${escapeHtml(diagnosis.cause)}
                </div>
            ` : ''}

            ${solutionsHtml}
            ${actionableHtml}
            ${securityHtml}

            <div class="diagnosis-actions">
                <button class="btn btn-primary" onclick="testWizardConnection('${integrationName}')">Retry Connection</button>
            </div>
        </div>
    `;
}

function hideDiagnosisPanel() {
    const panel = document.getElementById('wizard-diagnosis-panel');
    if (panel) {
        panel.style.display = 'none';
    }
}

/**
 * Apply a quick fix from AI diagnosis
 */
function applyQuickFix(integrationName, field, value) {
    if (!wizardState.configs[integrationName]) {
        wizardState.configs[integrationName] = {};
    }
    wizardState.configs[integrationName][field] = value;
    saveWizardState();
    showToast(`Applied fix: ${field} = ${value}`, 'success');
    hideDiagnosisPanel();
}

function applyHttpFix(integrationName) {
    const config = wizardState.configs[integrationName];
    if (config && config.url) {
        config.url = config.url.replace(/^https:/, 'http:');
        saveWizardState();
        showToast('Switched URL to HTTP', 'success');
        hideDiagnosisPanel();
    }
}

/**
 * Collect form data from current step
 */
function collectCurrentFormData(integrationName) {
    if (!wizardState.configs[integrationName]) {
        wizardState.configs[integrationName] = {};
    }

    const form = document.querySelector('.wizard-form');
    if (!form) return;

    form.querySelectorAll('input, select').forEach(input => {
        const name = input.name;
        if (!name) return;

        if (input.type === 'checkbox') {
            wizardState.configs[integrationName][name] = input.checked;
        } else if (input.type === 'password' && !input.value) {
            // Don't overwrite password if empty
        } else if (input.type === 'number') {
            wizardState.configs[integrationName][name] = parseInt(input.value) || 0;
        } else {
            wizardState.configs[integrationName][name] = input.value;
        }
    });
}

/** Dispatch table for wizard navigation — avoids eval(). */
const WIZARD_ACTIONS = {
    nextSubStep,
    previousSubStep,
    nextIntegration,
    previousIntegration,
    skipIntegration,
    goToStepSelect: () => goToStep('select'),
    goToStepSummary: () => goToStep('summary'),
};

function wizardDispatch(actionName) {
    const fn = WIZARD_ACTIONS[actionName];
    if (fn) fn();
}

/**
 * Save current sub-step data and continue
 */
function saveSubStepAndContinue(nextAction) {
    const currentIntegration = wizardState.selectedIntegrations[wizardState.currentIntegrationIndex];
    collectCurrentFormData(currentIntegration);
    saveWizardState();
    wizardDispatch(nextAction);
}

function nextSubStep() {
    wizardState.currentSubStep++;
    saveWizardState();
    renderConfigureStep();
}

function previousSubStep() {
    wizardState.currentSubStep--;
    saveWizardState();
    renderConfigureStep();
}

function nextIntegration() {
    wizardState.currentIntegrationIndex++;
    wizardState.currentSubStep = 0;
    saveWizardState();
    renderConfigureStep();
}

function previousIntegration() {
    wizardState.currentIntegrationIndex--;
    const prevIntegration = wizardState.selectedIntegrations[wizardState.currentIntegrationIndex];
    const subSteps = getSubSteps(prevIntegration);
    wizardState.currentSubStep = subSteps.length - 1;
    saveWizardState();
    renderConfigureStep();
}

function skipIntegration() {
    // Remove from selected and move on
    const skipped = wizardState.selectedIntegrations.splice(wizardState.currentIntegrationIndex, 1)[0];
    delete wizardState.configs[skipped];
    delete wizardState.testResults[skipped];

    if (wizardState.selectedIntegrations.length === 0) {
        goToStep('select');
    } else if (wizardState.currentIntegrationIndex >= wizardState.selectedIntegrations.length) {
        goToStep('summary');
    } else {
        wizardState.currentSubStep = 0;
        saveWizardState();
        renderConfigureStep();
    }
}

/**
 * Render summary step
 */
function renderSummaryStep() {
    const content = document.getElementById('wizard-content');
    const footer = document.getElementById('wizard-footer');

    let summaryHtml = '';
    for (const integrationName of wizardState.selectedIntegrations) {
        const meta = wizardState.integrationMeta[integrationName];
        const config = wizardState.configs[integrationName] || {};
        const testResult = wizardState.testResults[integrationName];

        let statusIcon = '?';
        let statusClass = 'unknown';
        if (testResult) {
            if (testResult.success) {
                statusIcon = '&#10003;';
                statusClass = 'success';
            } else {
                statusIcon = '&#10007;';
                statusClass = 'error';
            }
        }

        summaryHtml += `
            <div class="summary-item">
                <div class="summary-status ${statusClass}">${statusIcon}</div>
                <div class="summary-info">
                    <div class="summary-name">${escapeHtml(meta.name)}</div>
                    <div class="summary-config">
                        ${config.url ? `URL: ${escapeHtml(config.url)}` : ''}
                        ${config.enabled !== undefined ? ` | Enabled: ${config.enabled}` : ''}
                    </div>
                </div>
                <div class="summary-actions">
                    <button class="btn btn-sm" onclick="editIntegration('${integrationName}')">Edit</button>
                </div>
            </div>
        `;
    }

    content.innerHTML = `
        <div class="wizard-summary">
            <h3>Review & Save</h3>
            <p>Review your configuration before saving. All changes will be applied when you click Save.</p>

            <div class="summary-list">
                ${summaryHtml}
            </div>

            <div class="summary-note">
                <p><strong>Note:</strong> Only integrations with successful connection tests will be enabled automatically.
                Others will be saved but remain disabled.</p>
            </div>
        </div>
    `;

    footer.innerHTML = `
        <button class="btn btn-secondary" onclick="goToStep('configure')">Back to Configure</button>
        <button class="btn btn-primary" onclick="saveAllConfigurations()">Save All</button>
    `;
}

function editIntegration(integrationName) {
    const idx = wizardState.selectedIntegrations.indexOf(integrationName);
    if (idx >= 0) {
        wizardState.currentIntegrationIndex = idx;
        wizardState.currentSubStep = 0;
        goToStep('configure');
    }
}

/**
 * Save all configurations
 */
async function saveAllConfigurations() {
    const content = document.getElementById('wizard-content');
    content.innerHTML = `
        <div class="wizard-saving">
            <div class="spinner"></div>
            <p>Saving configurations...</p>
        </div>
    `;

    // Prepare configs with enabled flag based on test results
    const integrations = {};
    for (const integrationName of wizardState.selectedIntegrations) {
        const config = { ...wizardState.configs[integrationName] };
        const testResult = wizardState.testResults[integrationName];

        // Auto-enable if test succeeded
        if (testResult && testResult.success) {
            config.enabled = true;
        }

        integrations[integrationName] = config;
    }

    try {
        const response = await fetch('/api/admin/wizard/save-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ integrations }),
        });

        const result = await response.json();

        if (result.errors && result.errors.length > 0) {
            content.innerHTML = `
                <div class="wizard-result partial">
                    <h3>Partially Saved</h3>
                    <p>Some integrations were saved, but there were errors:</p>
                    <ul>
                        ${result.errors.map(e => `<li>${escapeHtml(e.integration)}: ${escapeHtml(e.error)}</li>`).join('')}
                    </ul>
                    <p>Saved: ${result.saved.join(', ')}</p>
                </div>
            `;
        } else {
            clearWizardState();
            content.innerHTML = `
                <div class="wizard-result success">
                    <div class="success-icon">&#10003;</div>
                    <h3>Configuration Complete!</h3>
                    <p>All integrations have been configured successfully.</p>
                    <p>Saved: ${result.saved.join(', ')}</p>
                </div>
            `;
        }

        document.getElementById('wizard-footer').innerHTML = `
            <button class="btn btn-primary" onclick="closeWizard(); loadAllSettings();">Done</button>
        `;

    } catch (error) {
        content.innerHTML = `
            <div class="wizard-result error">
                <h3>Save Failed</h3>
                <p>${escapeHtml(error.message)}</p>
            </div>
        `;
        document.getElementById('wizard-footer').innerHTML = `
            <button class="btn btn-secondary" onclick="goToStep('summary')">Back</button>
            <button class="btn btn-primary" onclick="saveAllConfigurations()">Retry</button>
        `;
    }
}

/**
 * Navigate to a specific step
 */
function goToStep(step) {
    wizardState.currentStep = step;
    if (step === 'configure') {
        // Reset to first integration if coming from select
        if (wizardState.currentIntegrationIndex >= wizardState.selectedIntegrations.length) {
            wizardState.currentIntegrationIndex = 0;
        }
        wizardState.currentSubStep = 0;

        // Prefetch Ollama models if Ollama is selected
        if (wizardState.selectedIntegrations.includes('ollama')) {
            fetchOllamaModels();
        }
    }
    saveWizardState();
    renderCurrentStep();
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchIntegrations() {
    try {
        const response = await fetch('/api/admin/wizard/integrations', {
            credentials: 'include'
        });
        if (!response.ok) throw new Error('Failed to fetch integrations');
        return await response.json();
    } catch (error) {
        showToast('Error loading integrations: ' + error.message, 'error');
        return null;
    }
}

async function fetchOllamaModels() {
    try {
        const response = await fetch('/api/admin/wizard/ollama/models', {
            credentials: 'include'
        });
        const data = await response.json();
        if (data.available && data.models) {
            ollamaModelsCache = data.models.map(m => m.name || m);
        }
    } catch (error) {
        console.error('Failed to fetch Ollama models:', error);
    }
}

// =============================================================================
// Initialization
// =============================================================================

// Export functions for global access
window.openIntegrationWizard = openIntegrationWizard;
window.closeWizard = closeWizard;
window.toggleIntegration = toggleIntegration;
window.selectAllIntegrations = selectAllIntegrations;
window.selectUnconfigured = selectUnconfigured;
window.clearSelection = clearSelection;
window.goToStep = goToStep;
window.startFresh = startFresh;
window.nextSubStep = nextSubStep;
window.previousSubStep = previousSubStep;
window.nextIntegration = nextIntegration;
window.previousIntegration = previousIntegration;
window.skipIntegration = skipIntegration;
window.saveSubStepAndContinue = saveSubStepAndContinue;
window.testWizardConnection = testWizardConnection;
window.requestAIDiagnosis = requestAIDiagnosis;
window.hideDiagnosisPanel = hideDiagnosisPanel;
window.applyQuickFix = applyQuickFix;
window.applyHttpFix = applyHttpFix;
window.editIntegration = editIntegration;
window.saveAllConfigurations = saveAllConfigurations;
