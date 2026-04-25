document.addEventListener('DOMContentLoaded', async () => {
  const loadingState = document.getElementById('loading-state');
  const scanPrompt = document.getElementById('scan-prompt');
  const assessmentPanel = document.getElementById('assessment-panel');
  const errorPanel = document.getElementById('error-panel');

  const scoreCircle = document.getElementById('score-circle');
  const scoreNumber = document.getElementById('score-number');
  const riskBadge = document.getElementById('risk-badge');
  const domainText = document.getElementById('domain-text');
  const summaryText = document.getElementById('summary-text');
  const flagsSection = document.getElementById('flags-section');
  const flagsList = document.getElementById('flags-list');

  const confirmBtn = document.getElementById('confirm-btn');
  const correctBtn = document.getElementById('correct-btn');
  const correctionForm = document.getElementById('correction-form');
  const submitCorrectionBtn = document.getElementById('submit-correction');
  const correctionStatus = document.getElementById('correction-status');
  const scanBtn = document.getElementById('scan-btn');
  const openOptionsLink = document.getElementById('open-options-link');

  let currentAssessment = null;
  let currentDomain = null;

  function hideAll() {
    loadingState.classList.add('hidden');
    scanPrompt.classList.add('hidden');
    assessmentPanel.classList.add('hidden');
    errorPanel.classList.add('hidden');
  }

  function showAssessment(assessment, domain) {
    hideAll();
    currentAssessment = assessment;
    currentDomain = domain;

    const level = assessment.risk_level || 'safe';
    const score = assessment.risk_score || 0;

    scoreCircle.className = 'score-circle ' + level;
    scoreNumber.textContent = score;
    riskBadge.className = 'risk-badge ' + level;
    riskBadge.textContent = level.charAt(0).toUpperCase() + level.slice(1);
    domainText.textContent = domain;
    summaryText.textContent = assessment.summary || 'No information available.';

    flagsList.innerHTML = '';
    const flags = assessment.flags || [];
    if (flags.length > 0) {
      flagsSection.classList.remove('hidden');
      flags.forEach(flag => {
        const li = document.createElement('li');
        li.textContent = flag;
        if (level === 'threat') li.classList.add('threat-flag');
        flagsList.appendChild(li);
      });
    } else {
      flagsSection.classList.add('hidden');
    }

    correctionForm.classList.add('hidden');
    correctionStatus.classList.add('hidden');
    assessmentPanel.classList.remove('hidden');
  }

  function showError(message) {
    hideAll();
    document.getElementById('error-text').textContent = message || 'Unable to assess this page.';
    errorPanel.classList.remove('hidden');
  }

  // Load assessment for current tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      showError('No active page to assess.');
      return;
    }

    let domain;
    try {
      domain = new URL(tab.url).hostname;
    } catch {
      showError('Cannot assess this type of page.');
      return;
    }

    if (!domain || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      showError('Cannot assess browser internal pages.');
      return;
    }

    const assessment = await chrome.runtime.sendMessage({ type: 'GET_ASSESSMENT', tabId: tab.id });

    if (!assessment) {
      hideAll();
      scanPrompt.classList.remove('hidden');
      currentDomain = domain;

      scanBtn.addEventListener('click', async () => {
        hideAll();
        loadingState.classList.remove('hidden');
        chrome.runtime.sendMessage({ type: 'REQUEST_SCAN', tab: { id: tab.id, url: tab.url } });

        setTimeout(async () => {
          const retryAssessment = await chrome.runtime.sendMessage({ type: 'GET_ASSESSMENT', tabId: tab.id });
          if (retryAssessment && retryAssessment.risk_level !== 'unknown') {
            showAssessment(retryAssessment, domain);
          } else {
            showError('Assessment timed out. Please try again.');
          }
        }, 3000);
      });
      return;
    }

    if (assessment.source === 'local_pending') {
      hideAll();
      scanPrompt.classList.remove('hidden');
      currentDomain = domain;

      const scanPromptText = document.querySelector('.scan-prompt-text');
      scanPromptText.textContent = 'Suspicious patterns detected. Scan for full assessment.';

      scanBtn.addEventListener('click', async () => {
        hideAll();
        loadingState.classList.remove('hidden');
        chrome.runtime.sendMessage({ type: 'REQUEST_SCAN', tab: { id: tab.id, url: tab.url } });

        setTimeout(async () => {
          const retryAssessment = await chrome.runtime.sendMessage({ type: 'GET_ASSESSMENT', tabId: tab.id });
          if (retryAssessment) {
            showAssessment(retryAssessment, domain);
          } else {
            showError('Assessment unavailable. Try refreshing the page.');
          }
        }, 3000);
      });
      return;
    }

    showAssessment(assessment, domain);

  } catch (err) {
    showError('Error loading assessment.');
  }

  // Correction handlers
  confirmBtn.addEventListener('click', () => {
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Thanks!';
    correctBtn.classList.add('hidden');
  });

  correctBtn.addEventListener('click', () => {
    correctionForm.classList.toggle('hidden');
  });

  submitCorrectionBtn.addEventListener('click', async () => {
    submitCorrectionBtn.disabled = true;
    const correctedLevel = document.getElementById('corrected-level').value;
    const note = document.getElementById('correction-note').value;

    const result = await chrome.runtime.sendMessage({
      type: 'SUBMIT_CORRECTION',
      data: {
        domain: currentDomain,
        original_score: currentAssessment ? currentAssessment.risk_score : 0,
        corrected_level: correctedLevel,
        note: note
      }
    });

    correctionStatus.classList.remove('hidden');
    if (result && result.success) {
      correctionStatus.textContent = 'Correction submitted. Thank you!';
      correctionStatus.className = 'correction-status success';
    } else {
      correctionStatus.textContent = 'Failed to submit. Try again later.';
      correctionStatus.className = 'correction-status error';
      submitCorrectionBtn.disabled = false;
    }
  });

  openOptionsLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
});
