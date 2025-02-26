// Listen for messages from the popup
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === 'fillCredential') {
    autofillCredentials(request.data, request.username);
    sendResponse({success: true});
  } else if (request.action === 'checkPage') {
    // Just for checking if content script is loaded
    sendResponse({success: true});
  }
  return true;
});

// Autofill credentials function
function autofillCredentials(password, username = '') {
  // Find all input fields
  const inputs = document.querySelectorAll('input');
  
  // Find password fields
  const passwordFields = Array.from(inputs).filter(input => 
    input.type === 'password'
  );
  
  // If no password fields, try to find hidden password fields
  if (passwordFields.length === 0) {
    const hiddenPasswordFields = Array.from(inputs).filter(input => 
      input.name && input.name.toLowerCase().includes('pass')
    );
    
    if (hiddenPasswordFields.length > 0) {
      hiddenPasswordFields.forEach(field => {
        field.value = password;
        triggerInputEvents(field);
      });
    }
    
    return;
  }
  
  // Fill password fields
  passwordFields.forEach(field => {
    field.value = password;
    triggerInputEvents(field);
  });
  
  // If username is provided, try to find and fill username field
  if (username) {
    // Look for username/email fields that appear before the password field
    const usernameField = findUsernameField(inputs, passwordFields[0]);
    
    if (usernameField) {
      usernameField.value = username;
      triggerInputEvents(usernameField);
    }
  }
  
  // Try to find and click submit button
  setTimeout(() => {
    tryClickSubmitButton();
  }, 500);
}

// Find the username field
function findUsernameField(inputs, passwordField) {
  // Get the form containing the password field
  const form = passwordField.form || findParentForm(passwordField);
  
  // First, look in the same form
  if (form) {
    // Look for fields with specific attributes or names
    const usernameField = Array.from(form.querySelectorAll('input')).find(input => {
      // Check if it's before the password field in the DOM
      if (input === passwordField || !isBeforeNode(input, passwordField)) {
        return false;
      }
      
      // Check input attributes
      return isLikelyUsernameField(input);
    });
    
    if (usernameField) {
      return usernameField;
    }
  }
  
  // If no form or no username field found in form, look in the whole document
  const usernameField = Array.from(inputs).find(input => {
    // Check if it's before the password field in the DOM
    if (input === passwordField || !isBeforeNode(input, passwordField)) {
      return false;
    }
    
    // Check input attributes
    return isLikelyUsernameField(input);
  });
  
  return usernameField;
}

// Check if an input field is likely a username field
function isLikelyUsernameField(input) {
  if (input.type === 'password' || input.type === 'hidden' || input.type === 'submit' || 
      input.type === 'button' || input.type === 'checkbox' || input.type === 'radio') {
    return false;
  }
  
  const inputType = input.type.toLowerCase();
  const inputId = (input.id || '').toLowerCase();
  const inputName = (input.name || '').toLowerCase();
  const placeholder = (input.placeholder || '').toLowerCase();
  const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
  
  // Check for email type
  if (inputType === 'email') {
    return true;
  }
  
  // Check for common username/email attributes
  const usernameTerms = ['user', 'name', 'email', 'login', 'account', 'id', 'username'];
  
  for (const term of usernameTerms) {
    if (inputId.includes(term) || inputName.includes(term) || 
        placeholder.includes(term) || ariaLabel.includes(term)) {
      return true;
    }
  }
  
  // If only one visible text field before password, it's likely the username
  return input.type === 'text' && input.style.display !== 'none' && input.style.visibility !== 'hidden';
}

// Find parent form of an element
function findParentForm(element) {
  let parent = element.parentElement;
  while (parent) {
    if (parent.tagName === 'FORM') {
      return parent;
    }
    parent = parent.parentElement;
  }
  return null;
}

// Check if nodeA comes before nodeB in the DOM
function isBeforeNode(nodeA, nodeB) {
  return (nodeA.compareDocumentPosition(nodeB) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
}

// Trigger input events to simulate user typing
function triggerInputEvents(element) {
  // Create and dispatch input event
  const inputEvent = new Event('input', { bubbles: true });
  element.dispatchEvent(inputEvent);
  
  // Create and dispatch change event
  const changeEvent = new Event('change', { bubbles: true });
  element.dispatchEvent(changeEvent);
}

// Try to find and click the submit button
function tryClickSubmitButton() {
  // Look for submit buttons
  const submitButtons = Array.from(document.querySelectorAll('button[type="submit"], input[type="submit"]'));
  
  // If no explicit submit buttons, look for buttons inside forms
  if (submitButtons.length === 0) {
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const buttons = Array.from(form.querySelectorAll('button:not([type]), button[type="button"]'));
      submitButtons.push(...buttons);
    }
  }
  
  // If still no buttons, look for elements that might act as submit buttons
  if (submitButtons.length === 0) {
    const potentialButtons = Array.from(document.querySelectorAll('a, div, span, button'))
      .filter(el => {
        const text = (el.textContent || '').toLowerCase();
        return (
          text.includes('login') || 
          text.includes('sign in') || 
          text.includes('log in') ||
          text.includes('continue')
        );
      });
    
    submitButtons.push(...potentialButtons);
  }
  
  // Don't automatically click the button - it's too intrusive
  // Just highlight it instead
  if (submitButtons.length > 0) {
    const button = submitButtons[0];
    const originalBackground = button.style.backgroundColor;
    const originalBoxShadow = button.style.boxShadow;
    
    button.style.backgroundColor = 'rgba(74, 144, 226, 0.3)';
    button.style.boxShadow = '0 0 5px 2px rgba(74, 144, 226, 0.5)';
    
    setTimeout(() => {
      button.style.backgroundColor = originalBackground;
      button.style.boxShadow = originalBoxShadow;
    }, 2000);
  }
}