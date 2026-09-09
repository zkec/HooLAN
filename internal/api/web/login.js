'use strict';

(function () {
  var form = document.getElementById('login-form');
  var token = document.getElementById('login-token');
  var button = document.getElementById('login-submit');
  var errorBox = document.getElementById('login-error');
  var submitting = false;

  function error(message) {
    errorBox.textContent = message;
    errorBox.hidden = !message;
  }
  async function session() {
    var response = await fetch('/api/auth/session', { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json' } });
    if (!response.ok) return;
    var data = await response.json();
    if (data.authenticated || !data.auth_required) window.location.replace('/');
  }
  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (submitting || !token.value) return;
    submitting = true;
    button.disabled = true;
    button.textContent = 'Signing in…';
    error('');
    try {
      var response = await fetch('/api/auth/login', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ token: token.value })
      });
      token.value = '';
      var data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Sign-in failed. Check your access token.');
      if (!data.authenticated && data.auth_required) throw new Error('The server could not create a session. Please try again.');
      window.location.replace('/');
    } catch (failure) {
      error(failure instanceof TypeError ? 'Cannot reach the gateway. Check your connection and try again.' : failure.message);
      token.value = '';
      token.focus();
      submitting = false;
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  });
  try { window.localStorage.removeItem('pm.token'); window.localStorage.removeItem('pm.subUrl'); } catch (ignored) {}
  window.addEventListener('pagehide', function () { token.value = ''; });
  session().catch(function () { error('Cannot reach the gateway. You can retry signing in when it is available.'); });
}());
