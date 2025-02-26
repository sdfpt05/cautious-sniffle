// Listen for extension installation
chrome.runtime.onInstalled.addListener(function() {
  console.log("Data Privacy Vault extension installed");
});

// Context menu for credential autofill
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "fill-credentials",
    title: "Autofill with Data Privacy Vault",
    contexts: ["page"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "fill-credentials") {
    // Open the popup
    chrome.action.openPopup();
  }
});

// Check for token expiration
chrome.alarms.create('tokenCheck', { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'tokenCheck') {
    checkTokenExpiration();
  }
});

// Function to check if token is expired and refresh if needed
function checkTokenExpiration() {
  chrome.storage.local.get(['token', 'refreshToken', 'tokenExpiry', 'serverUrl'], function(result) {
    if (!result.token || !result.tokenExpiry || !result.refreshToken || !result.serverUrl) {
      return;
    }
    
    const now = new Date();
    const expiry = new Date(result.tokenExpiry);
    
    // If token expires in less than 5 minutes, refresh it
    const fiveMinutesFromNow = new Date(now.getTime() + 5 * 60 * 1000);
    
    if (expiry <= fiveMinutesFromNow) {
      refreshToken(result.serverUrl, result.refreshToken);
    }
  });
}

// Function to refresh the token
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
      });
    }
  })
  .catch(error => {
    console.error('Error refreshing token:', error);
  });
}

// Automatic login on specific sites
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Get the domain from the URL
    const url = new URL(tab.url);
    const domain = url.hostname;
    
    // Check if we have credentials for this domain
    chrome.storage.local.get(['token', 'serverUrl'], function(result) {
      if (!result.token || !result.serverUrl) {
        return;
      }
      
      // Check if this is a login page
      if (isLikelyLoginPage(tab.url, tab.title)) {
        // Notify the user that credentials are available
        chrome.action.setBadgeText({ text: "✓", tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#4CAF50", tabId: tabId });
        
        // After 5 seconds, remove the badge
        setTimeout(() => {
          chrome.action.setBadgeText({ text: "", tabId: tabId });
        }, 5000);
      } else {
        chrome.action.setBadgeText({ text: "", tabId: tabId });
      }
    });
  }
});

// Check if the current page is likely a login page
function isLikelyLoginPage(url, title) {
  // Check URL for login-related terms
  const urlLower = url.toLowerCase();
  const titleLower = title.toLowerCase();
  
  const loginTerms = ['login', 'signin', 'sign-in', 'log-in', 'logon', 'authenticate'];
  
  // Check URL
  for (const term of loginTerms) {
    if (urlLower.includes(term)) {
      return true;
    }
  }
  
  // Check title
  for (const term of loginTerms) {
    if (titleLower.includes(term)) {
      return true;
    }
  }
  
  return false;
}

// Token cleanup - periodically check for expired tokens in storage
chrome.alarms.create('tokenCleanup', { periodInMinutes: 60 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'tokenCleanup') {
    chrome.storage.local.get(['tokenExpiry'], function(result) {
      if (result.tokenExpiry) {
        const now = new Date();
        const expiry = new Date(result.tokenExpiry);
        
        // If token expired more than a day ago, clean up
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        if (expiry < oneDayAgo) {
          chrome.storage.local.remove(['token', 'refreshToken', 'tokenExpiry']);
        }
      }
    });
  }
});