document.addEventListener('DOMContentLoaded', async () => {
  const modeClick = document.getElementById('mode-click');
  const modeAlways = document.getElementById('mode-always');
  const permissionStatus = document.getElementById('permission-status');
  const showBadge = document.getElementById('show-badge');
  const whitelistInput = document.getElementById('whitelist-input');
  const whitelistAdd = document.getElementById('whitelist-add');
  const whitelistList = document.getElementById('whitelist-list');
  const whitelistEmpty = document.getElementById('whitelist-empty');

  // Load current settings
  const { settings = {}, whitelist = [] } = await chrome.storage.local.get(['settings', 'whitelist']);

  showBadge.checked = settings.showBadge !== false;

  // Check current permission state
  const hasAllUrls = await new Promise(resolve => {
    chrome.permissions.contains({ origins: ['<all_urls>'] }, resolve);
  });

  if (hasAllUrls && settings.alwaysOn) {
    modeAlways.checked = true;
    permissionStatus.textContent = 'Permission granted. Always-on protection is active.';
    permissionStatus.className = 'permission-note granted';
    permissionStatus.classList.remove('hidden');
  } else {
    modeClick.checked = true;
  }

  // Protection mode change
  modeAlways.addEventListener('change', async () => {
    if (!modeAlways.checked) return;

    chrome.permissions.request({ origins: ['<all_urls>'] }, (granted) => {
      if (granted) {
        permissionStatus.textContent = 'Permission granted. Always-on protection is active.';
        permissionStatus.className = 'permission-note granted';
        permissionStatus.classList.remove('hidden');
        saveSettings({ alwaysOn: true });
      } else {
        modeClick.checked = true;
        permissionStatus.textContent = 'Permission denied. Using click-to-scan mode.';
        permissionStatus.className = 'permission-note denied';
        permissionStatus.classList.remove('hidden');
        saveSettings({ alwaysOn: false });
      }
    });
  });

  modeClick.addEventListener('change', () => {
    if (!modeClick.checked) return;
    permissionStatus.classList.add('hidden');
    saveSettings({ alwaysOn: false });
  });

  showBadge.addEventListener('change', () => {
    saveSettings({ showBadge: showBadge.checked });
  });

  async function saveSettings(updates) {
    const { settings: current = {} } = await chrome.storage.local.get('settings');
    await chrome.storage.local.set({ settings: { ...current, ...updates } });
  }

  // Whitelist management
  function renderWhitelist(list) {
    whitelistList.innerHTML = '';
    if (list.length === 0) {
      whitelistEmpty.classList.remove('hidden');
      return;
    }
    whitelistEmpty.classList.add('hidden');

    list.forEach(domain => {
      const li = document.createElement('li');
      li.innerHTML = `
        <span>${escapeHtml(domain)}</span>
        <button class="whitelist-remove" data-domain="${escapeHtml(domain)}">Remove</button>
      `;
      whitelistList.appendChild(li);
    });

    whitelistList.querySelectorAll('.whitelist-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        const domain = btn.dataset.domain;
        const { whitelist: current = [] } = await chrome.storage.local.get('whitelist');
        const updated = current.filter(d => d !== domain);
        await chrome.storage.local.set({ whitelist: updated });
        renderWhitelist(updated);
      });
    });
  }

  renderWhitelist(whitelist);

  whitelistAdd.addEventListener('click', async () => {
    const domain = whitelistInput.value.trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');

    if (!domain || !domain.includes('.')) return;

    const { whitelist: current = [] } = await chrome.storage.local.get('whitelist');
    if (current.includes(domain)) return;

    const updated = [...current, domain];
    await chrome.storage.local.set({ whitelist: updated });
    renderWhitelist(updated);
    whitelistInput.value = '';
  });

  whitelistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') whitelistAdd.click();
  });

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
});
