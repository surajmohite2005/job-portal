// auth.js - Shared Authentication & Utility for Job Portal

/**
 * Checks if the user is authenticated and redirects if necessary.
 * @param {string} [redirectPath='/login.html'] - Path to redirect to if not authenticated.
 * @returns {Promise<object|null>} - Resolves with user data if authenticated, otherwise null.
 */
async function checkAuthentication(redirectPath = '/login.html') {
    try {
        const response = await fetch('/api/me', { credentials: 'include' });
        if (!response.ok) {
            window.location.href = redirectPath;
            return null;
        }
        return await response.json();
    } catch (error) {
        console.error('Authentication check failed:', error);
        window.location.href = redirectPath;
        return null;
    }
}

/**
 * Logs out the user by clearing the cookie and redirecting to the homepage.
 */
async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST', credentials: 'include' });
        window.location.href = '/';
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/';
    }
}

/**
 * Fetches the CSRF token from the server.
 * @returns {Promise<string>} The CSRF token.
 */
async function getCsrfToken() {
    try {
        const response = await fetch('/api/csrf-token', { 
            method: 'GET',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Failed to fetch CSRF token: ${response.status}`);
        }
        
        const data = await response.json();
        return data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        throw error;
    }
}

/**
 * Gets the CSRF token from cookies (fallback method).
 * @returns {string|null} The CSRF token from cookies.
 */
function getCsrfTokenFromCookie() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'XSRF-TOKEN') {
            return value;
        }
    }
    return null;
}

/**
 * A reusable function to show a message on the UI.
 * @param {HTMLElement} element - The DOM element to display the message in.
 * @param {string} message - The message text.
 * @param {'success'|'error'} type - The type of message.
 */
function showMessage(element, message, type) {
    element.textContent = message;
    element.className = `mt-4 p-3 rounded-lg ${type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`;
    element.classList.remove('hidden');
    setTimeout(() => { element.classList.add('hidden'); }, 5000);
}