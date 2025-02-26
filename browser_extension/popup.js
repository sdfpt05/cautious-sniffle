document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const loginForm = document.getElementById('loginForm');
  const credentialList = document.getElementById('credentialList');
  const credentialDetail = document.getElementById('credentialDetail');
  const credentials = document.getElementById('credentials');
  const statusMessage = document.getElementById('statusMessage');
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const refreshBtn = document.getElementById('refreshBtn');
  const backBtn = document.getElementById('backBtn');
  const mfaGroup = document.getElementById('mfaGroup');
  const searchInput = document.getElementById('searchInput');
  const categoryFilter = document.getElementById('categoryFilter');
  const detailName = document.getElementById('detailName');
  const detailData = document.getElementById('detailData');
  const detailCategory = document.getElementById('detailCategory');
  const detailUrl = document.getElementById('detailUrl');
  const detailNotes = document.getElementById('detailNotes');
  const categoryRow = document.getElementById('categoryRow');
  const urlRow = document.getElementById('urlRow');
  const notesRow = document.getElementById('notesRow');
  const togglePassword = document.getElementById('togglePassword');
  const copyData = document.getElementById('copyData');
  const autofillBtn = document.getElementById('autofillBtn');
  
  // Current state
  let allCredentials = [];
  let currentCredential = null;
  let currentTabUrl = '';
  
  // Get current tab URL for matching
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs.length > 0 && tabs[0].url) {
      currentTabUrl = new URL(tabs[0].url).hostname;
    }
  });
  
  // Check if user is already logged in
  chrome.storage.local.get(['token', 'serverUrl', 'refreshToken', 'tokenExpiry'], function(result) {
    if (result.token && result.serverUrl) {
      // Check if token is expired
      const now = new Date();
      const expiry = new Date(result.tokenExpiry);
      
      if (now >= expiry && result.refreshToken) {
        // Try to refresh the token
        refreshToken(result.serverUrl, result.refreshToken);
      } else {
        // Token is still valid, fetch credentials
        document.getElementById('serverUrl').value = result.serverUrl;
        fetchCredentials(result.serverUrl, result.token);
      }
    }
  });
  
  // Event listeners
  loginBtn.addEventListener('click', handleLogin);
  logoutBtn.addEventListener('click', handleLogout);
  refreshBtn.addEventListener('click', handleRefresh);
  backBtn.addEventListener('click', showCredentialList);
  togglePassword.addEventListener('click', togglePasswordVisibility);
  copyData.addEventListener('click', copyCredentialData);
  autofillBtn.addEventListener('click', handleAutofill);
  searchInput.addEventListener('input', filterCredentials);
  categoryFilter.addEventListener('change', filterCredentials);
  
  // Functions
  function handleLogin() {
    const serverUrl = document.getElementById('serverUrl').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const mfaCode = document.getElementById('mfaCode').value;
    
    if (!serverUrl || !username || !password) {
      showStatus('Please fill in all required fields', 'error');
      return;
    }
    
    // Clear previous status
    showStatus('');
    loginBtn.textContent = 'Logging in...';
    loginBtn.disabled = true;
    
    // Login request
    const loginData = {
      username: username,
      password: password
    };
    
    if (mfaCode) {
      loginData.mfa_code = mfaCode;
    }
    
    fetch(`${serverUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(loginData)
    })
    .then(response => response.json())
    .then(data => {
      if (data.require_mfa) {
        // Show MFA input
        mfaGroup.classList.remove('hidden');
        showStatus('Please enter your MFA code', 'info');
        loginBtn.textContent = 'Login';
        loginBtn.disabled = false;
        return;
      }
      
      if (data.access_token) {
        // Calculate token expiry (30 minutes from now)
        const expiry = new Date();
        expiry.setMinutes(expiry.getMinutes() + 30);
        
        // Store token and server URL
        chrome.storage.local.set({
          token: data.access_token,
          refreshToken: data.refresh_token,
          serverUrl: serverUrl,
          tokenExpiry: expiry.toISOString(),
          user: data.user
        }, function() {
          // Fetch credentials after successful login
          fetchCredentials(serverUrl, data.access_token);
        });
      } else {
        showStatus(data.msg || 'Login failed', 'error');
        loginBtn.textContent = 'Login';
        loginBtn.disabled = false;
      }
    })
    .catch(error => {
      showStatus(`Network error: ${error.message}`, 'error');
      loginBtn.textContent = 'Login';
      loginBtn.disabled = false;
    });
  }
  
  function handleLogout() {
    const serverUrl = document.getElementById('serverUrl').value;
    
    chrome.storage.local.get(['token'], function(result) {
      if (result.token) {
        // Logout from server
        fetch(`${serverUrl}/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${result.token}`,
            'Content-Type': 'application/json'
          }
        }).catch(() => {
          // Ignore errors on logout
        });
      }
      
      // Clear stored data
      chrome.storage.local.remove(['token', 'refreshToken', 'serverUrl', 'tokenExpiry', 'user'], function() {
        // Reset UI
        resetUI();
        showStatus('Logged out successfully', 'success');
      });
    });
  }
  
  function handleRefresh() {
    chrome.storage.local.get(['token', 'serverUrl'], function(result) {
      if (result.token && result.serverUrl) {
        fetchCredentials(result.serverUrl, result.token);
      }
    });
  }
  
  function fetchCredentials(serverUrl, token) {
    // Show loading status
    showStatus('Loading credentials...', 'info');
    
    fetch(`${serverUrl}/api/credentials`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => {
      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Authentication expired. Please log in again.');
        }
        throw new Error(`Server error: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      // Store credentials
      allCredentials = data;
      
      // Show credential list
      loginForm.classList.add('hidden');
      credentialList.classList.remove('hidden');
      credentialDetail.classList.add('hidden');
      
      // Populate categories filter
      populateCategoryFilter(data);
      
      // Display credentials
      displayCredentials(data);
      
      // Clear status
      showStatus('');
    })
    .catch(error => {
      if (error.message.includes('Authentication expired')) {
        // Try to refresh the token
        chrome.storage.local.get(['refreshToken', 'serverUrl'], function(result) {
          if (result.refreshToken && result.serverUrl) {
            refreshToken(result.serverUrl, result.refreshToken);
          } else {
            // Show login form again
            resetUI();
            showStatus(error.message, 'error');
          }
        });
      } else {
        // Show login form again
        resetUI();
        showStatus(`Error: ${error.message}`, 'error');
      }
    });
  }
  
  function refreshToken(serverUrl, refreshToken) {
    fetch(`${serverUrl}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${refreshToken}`,
        'Content-Type': 'application/json'
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.access_token) {
        // Calculate token expiry (30 minutes from now)
        const expiry = new Date();
        expiry.setMinutes(expiry.getMinutes() + 30);
        
        // Store new token
        chrome.storage.local.set({
          token: data.access_token,
          tokenExpiry: expiry.toISOString()
        }, function() {
          // Fetch credentials with new token
          fetchCredentials(serverUrl, data.access_token);
        });
      } else {
        // Refresh failed, show login
        resetUI();
        showStatus('Session expired. Please log in again.', 'error');
      }
    })
    .catch(error => {
      // Refresh failed, show login
      resetUI();
      showStatus(`Authentication error: ${error.message}`, 'error');
    });
  }
  
  function populateCategoryFilter(data) {
    // Clear existing options except the first one
    while (categoryFilter.options.length > 1) {
      categoryFilter.remove(1);
    }
    
    // Get unique categories
    const categories = [...new Set(data
      .map(cred => cred.category)
      .filter(category => category) // Remove null/empty categories
    )].sort();
    
    // Add options
    categories.forEach(category => {
      const option = document.createElement('option');
      option.value = category;
      option.textContent = category;
      categoryFilter.appendChild(option);
    });
  }
  
  function displayCredentials(data) {
    // Clear previous credentials
    credentials.innerHTML = '';
    
    if (data.length === 0) {
      credentials.innerHTML = '<p>No credentials found</p>';
      return;
    }
    
    // Sort by name
    data.sort((a, b) => a.name.localeCompare(b.name));
    
    // Group by matching current URL first
    const matchingCredentials = [];
    const otherCredentials = [];
    
    data.forEach(cred => {
      if (cred.url && currentTabUrl && cred.url.includes(currentTabUrl)) {
        matchingCredentials.push(cred);
      } else {
        otherCredentials.push(cred);
      }
    });
    
    // Combine the arrays with matching credentials first
    const sortedCredentials = [...matchingCredentials, ...otherCredentials];
    
    // Display credentials
    sortedCredentials.forEach(cred => {
      const credItem = document.createElement('div');
      credItem.className = 'credential-item';
      
      const credTitle = document.createElement('div');
      credTitle.className = 'title';
      
      // Add favorite star if applicable
      if (cred.favorite) {
        const star = document.createElement('span');
        star.className = 'favorite';
        star.textContent = '★';
        credTitle.appendChild(star);
      }
      
      // Add matching indicator if URL matches current tab
      if (cred.url && currentTabUrl && cred.url.includes(currentTabUrl)) {
        const match = document.createElement('span');
        match.className = 'match';
        match.textContent = '✓ ';
        match.style.color = 'green';
        credTitle.appendChild(match);
      }
      
      credTitle.appendChild(document.createTextNode(cred.name));
      
      const credCategory = document.createElement('div');
      credCategory.className = 'category';
      credCategory.textContent = cred.category || 'Uncategorized';
      
      credItem.appendChild(credTitle);
      credItem.appendChild(credCategory);
      
      credItem.addEventListener('click', () => {
        showCredentialDetail(cred);
      });
      
      credentials.appendChild(credItem);
    });
  }
  
  function filterCredentials() {
    const searchTerm = searchInput.value.toLowerCase();
    const categoryValue = categoryFilter.value;
    
    const filteredCredentials = allCredentials.filter(cred => {
      const nameMatch = cred.name.toLowerCase().includes(searchTerm);
      const categoryMatch = !categoryValue || (cred.category === categoryValue);
      return nameMatch && categoryMatch;
    });
    
    displayCredentials(filteredCredentials);
  }
  
  function showCredentialDetail(credential) {
    currentCredential = credential;
    
    // Hide list, show detail
    credentialList.classList.add('hidden');
    credentialDetail.classList.remove('hidden');
    
    // Populate detail view
    detailName.textContent = credential.name;
    detailData.value = credential.data;
    detailData.type = 'password'; // Hide by default
    
    // Show/hide category
    if (credential.category) {
      categoryRow.classList.remove('hidden');
      detailCategory.textContent = credential.category;
    } else {
      categoryRow.classList.add('hidden');
    }
    
    // Show/hide URL
    if (credential.url) {
      urlRow.classList.remove('hidden');
      detailUrl.textContent = credential.url;
      detailUrl.onclick = () => {
        chrome.tabs.create({ url: ensureHttpPrefix(credential.url) });
      };
      detailUrl.style.cursor = 'pointer';
      detailUrl.style.color = '#4a90e2';
      detailUrl.style.textDecoration = 'underline';
    } else {
      urlRow.classList.add('hidden');
    }
    
    // Show/hide notes
    if (credential.notes) {
      notesRow.classList.remove('hidden');
      detailNotes.textContent = credential.notes;
    } else {
      notesRow.classList.add('hidden');
    }
    
    // Enable/disable autofill button based on current tab matching URL
    const credUrl = credential.url ? new URL(ensureHttpPrefix(credential.url)).hostname : '';
    if (credUrl && currentTabUrl && credUrl.includes(currentTabUrl) || 
        currentTabUrl && currentTabUrl.includes(credUrl)) {
      autofillBtn.disabled = false;
    } else {
      autofillBtn.disabled = true;
    }
  }
  
  function showCredentialList() {
    credentialDetail.classList.add('hidden');
    credentialList.classList.remove('hidden');
    currentCredential = null;
  }
  
  function togglePasswordVisibility() {
    if (detailData.type === 'password') {
      detailData.type = 'text';
      togglePassword.textContent = '🔒';
    } else {
      detailData.type = 'password';
      togglePassword.textContent = '👁️';
    }
  }
  
  function copyCredentialData() {
    if (currentCredential) {
      navigator.clipboard.writeText(currentCredential.data)
        .then(() => {
          showStatus('Copied to clipboard!', 'success');
          setTimeout(() => {
            showStatus('');
          }, 2000);
        })
        .catch(err => {
          showStatus('Failed to copy: ' + err, 'error');
        });
    }
  }
  
  function handleAutofill() {
    if (currentCredential) {
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs.length > 0) {
          chrome.tabs.sendMessage(tabs[0].id, {
            action: 'fillCredential',
            data: currentCredential.data,
            username: extractUsername(currentCredential)
          });
          
          showStatus('Credentials filled', 'success');
          setTimeout(() => {
            showStatus('');
          }, 2000);
        }
      });
    }
  }
  
  function extractUsername(credential) {
    // Try to extract username from notes or name
    if (credential.notes && credential.notes.toLowerCase().includes('username:')) {
      const match = credential.notes.match(/username:\s*([^\n]+)/i);
      if (match) return match[1].trim();
    }
    
    // Try to extract email-like parts from the name
    const emailMatch = credential.name.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (emailMatch) return emailMatch[1];
    
    return '';
  }
  
  function resetUI() {
    loginForm.classList.remove('hidden');
    credentialList.classList.add('hidden');
    credentialDetail.classList.add('hidden');
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('mfaCode').value = '';
    mfaGroup.classList.add('hidden');
    loginBtn.textContent = 'Login';
    loginBtn.disabled = false;
  }
  
  function showStatus(message, type = '') {
    statusMessage.textContent = message;
    statusMessage.className = 'status-message';
    
    if (type) {
      statusMessage.classList.add(type);
    }
  }
  
  function ensureHttpPrefix(url) {
    if (!url) return '';
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return 'https://' + url;
    }
    return url;
  }
});