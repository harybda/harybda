// --- Конфигурация ---
// !!! ВАЖНО: Замените эти значения на свои реальные CLIENT_ID и REDIRECT_URI !!!
const CLIENT_ID = '53013944'; // Ваш ID приложения VK ID
const REDIRECT_URI = 'https://harybda.github.io/harybda/'; // URL, на который VK ID перенаправит после авторизации

// Права доступа, разделенные пробелами. Например: 'email phone offline'
// 'offline' нужен для получения refresh_token
// 'account' добавлен для account.getProfileInfo
const SCOPES = 'vkid.personal_info offline email phone groups ads account';

// --- Элементы DOM ---
const loginButton = document.getElementById('loginButton');
const logoutButton = document.getElementById('logoutButton');
const getProfileInfoButton = document.getElementById('getProfileInfoButton'); // Новая кнопка
const messageDisplay = document.getElementById('messageDisplay');
const userInfoDisplay = document.getElementById('userInfoDisplay');
const profileDetailsDisplay = document.getElementById('profileDetailsDisplay'); // Новый элемент для деталей профиля

// --- Вспомогательные функции для PKCE ---

/**
 * Генерирует случайную строку заданной длины.
 * Используется для code_verifier и state.
 * @param {number} length Длина генерируемой строки.
 * @returns {string} Случайная строка.
 */
function generateRandomString(length) {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let text = '';
    for (let i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

/**
 * Вычисляет SHA-256 хеш от строки.
 * @param {string} plain Строка для хеширования.
 * @returns {Promise<ArrayBuffer>} Promise, который разрешается с ArrayBuffer хеша.
 */
async function sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return hashBuffer;
}

/**
 * Кодирует ArrayBuffer в Base64url.
 * @param {ArrayBuffer} buffer Буфер для кодирования.
 * @returns {string} Base64url-кодированная строка.
 */
function base64urlencode(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Генерирует code_verifier и code_challenge для PKCE.
 * @returns {Promise<{codeVerifier: string, codeChallenge: string}>} Объект с code_verifier и code_challenge.
 */
async function generatePKCE() {
    const codeVerifier = generateRandomString(128);
    const hashed = await sha256(codeVerifier);
    const codeChallenge = base64urlencode(hashed);
    return { codeVerifier, codeChallenge };
}

// --- Функции UI и состояния ---

/**
 * Отображает сообщение на экране.
 * @param {string} message Текст сообщения.
 * @param {string} type Тип сообщения ('success' или 'error').
 */
function showMessage(message, type) {
    messageDisplay.textContent = message;
    messageDisplay.className = `message ${type}`;
    messageDisplay.classList.remove('hidden');
}

/**
 * Очищает сообщение.
 */
function clearMessage() {
    messageDisplay.classList.add('hidden');
    messageDisplay.textContent = '';
}

/**
 * Отображает информацию о пользователе.
 * @param {Object} userInfo Объект с данными пользователя.
 */
function showUserInfo(userInfo) {
    userInfoDisplay.innerHTML = `
        <h3>Информация о пользователе:</h3>
        ${userInfo.avatar ? `<img src="${userInfo.avatar}" alt="Аватар пользователя">` : ''}
        <p><strong>ID:</strong> ${userInfo.user_id || 'N/A'}</p>
        <p><strong>Имя:</strong> ${userInfo.first_name || 'N/A'}</p>
        <p><strong>Фамилия:</strong> ${userInfo.last_name || 'N/A'}</p>
        <p><strong>Email:</strong> ${userInfo.email || 'N/A'}</p>
        <p><strong>Телефон:</strong> ${userInfo.phone || 'N/A'}</p>
    `;
    userInfoDisplay.classList.remove('hidden');
    loginButton.classList.add('hidden');
    logoutButton.classList.remove('hidden');
    getProfileInfoButton.classList.remove('hidden'); // Показываем кнопку получения профиля
}

/**
 * Скрывает информацию о пользователе и показывает кнопку входа.
 */
function hideUserInfo() {
    userInfoDisplay.classList.add('hidden');
    userInfoDisplay.innerHTML = '';
    profileDetailsDisplay.classList.add('hidden'); // Скрываем детали профиля
    profileDetailsDisplay.innerHTML = '';
    loginButton.classList.remove('hidden');
    logoutButton.classList.add('hidden');
    getProfileInfoButton.classList.add('hidden'); // Скрываем кнопку получения профиля
}

/**
 * Отображает подробную информацию о профиле.
 * @param {Object} profileInfo Объект с подробными данными профиля.
 */
function showProfileDetails(profileInfo) {
    let detailsHtml = `<h4>Подробная информация о профиле:</h4>`;
    for (const key in profileInfo) {
        if (profileInfo.hasOwnProperty(key)) {
            let value = profileInfo[key];
            if (typeof value === 'object' && value !== null) {
                if (value.title) { // Для объектов типа {id: ..., title: ...}
                    value = value.title;
                } else {
                    value = JSON.stringify(value); // Для других объектов
                }
            }
            detailsHtml += `<p><strong>${key}:</strong> ${value || 'N/A'}</p>`;
        }
    }
    profileDetailsDisplay.innerHTML = detailsHtml;
    profileDetailsDisplay.classList.remove('hidden');
}


// --- Основные функции авторизации ---

/**
 * Инициирует процесс авторизации VK ID.
 */
async function initiateVKIDLogin() {
    clearMessage();
    try {
        const { codeVerifier, codeChallenge } = await generatePKCE();
        const state = generateRandomString(32);

        sessionStorage.setItem('vk_code_verifier', codeVerifier);
        sessionStorage.setItem('vk_state', state);

        const authUrl = new URL('https://id.vk.com/authorize');
        authUrl.searchParams.append('response_type', 'code');
        authUrl.searchParams.append('client_id', CLIENT_ID);
        authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
        authUrl.searchParams.append('scope', SCOPES);
        authUrl.searchParams.append('state', state);
        authUrl.searchParams.append('code_challenge', codeChallenge);
        authUrl.searchParams.append('code_challenge_method', 'S256');

        window.location.assign(authUrl.toString());
    } catch (error) {
        console.error('Ошибка при инициализации авторизации:', error);
        showMessage('Не удалось начать процесс авторизации. Попробуйте снова.', 'error');
    }
}

/**
 * Обменивает авторизационный код на токены.
 * @param {string} code Код авторизации, полученный от VK ID.
 * @param {string} codeVerifier code_verifier, сохраненный ранее.
 * @param {string} deviceId Идентификатор устройства, полученный от VK ID.
 * @returns {Promise<Object>} Promise, который разрешается с объектом токенов.
 */
async function exchangeCodeForTokens(code, codeVerifier, deviceId) {
    const tokenUrl = 'https://id.vk.com/oauth2/auth';
    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('client_id', CLIENT_ID);
    params.append('code', code);
    params.append('code_verifier', codeVerifier);
    params.append('device_id', deviceId);
    params.append('redirect_uri', REDIRECT_URI);

    try {
        const response = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Ошибка при обмене кода: ${errorData.error_description || response.statusText}`);
        }

        const data = await response.json();
        console.log('Получены токены:', data);

        sessionStorage.setItem('vk_access_token', data.access_token);
        sessionStorage.setItem('vk_refresh_token', data.refresh_token);
        sessionStorage.setItem('vk_id_token', data.id_token);
        sessionStorage.setItem('vk_user_id', data.user_id);

        return data;
    } catch (error) {
        console.error('Ошибка обмена кода на токены:', error);
        throw error;
    }
}

/**
 * Получает информацию о пользователе с помощью Access Token.
 * @param {string} accessToken Access Token пользователя.
 * @returns {Promise<Object>} Promise, который разрешается с объектом информации о пользователе.
 */
async function getUserInfo(accessToken) {
    const userInfoUrl = 'https://id.vk.com/oauth2/user_info';
    const params = new URLSearchParams();
    params.append('access_token', accessToken);
    params.append('client_id', CLIENT_ID);

    try {
        const response = await fetch(userInfoUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Ошибка при получении информации о пользователе: ${errorData.error_description || response.statusText}`);
        }

        const data = await response.json();
        console.log('Информация о пользователе:', data);
        return data.user;
    } catch (error) {
        console.error('Ошибка получения информации о пользователе:', error);
        throw error;
    }
}

/**
 * Получает подробную информацию о профиле пользователя через account.getProfileInfo.
 * @param {string} accessToken Access Token пользователя.
 * @returns {Promise<Object>} Promise, который разрешается с объектом подробной информации о профиле.
 */
async function getAccountProfileInfo(accessToken) {
    const apiUrl = 'https://api.vk.com/method/account.getProfileInfo';
    const params = new URLSearchParams();
    params.append('access_token', accessToken);
    params.append('v', '5.131'); // Версия API VK

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Ошибка при получении информации о профиле: ${errorData.error_msg || response.statusText}`);
        }

        const data = await response.json();
        if (data.error) {
            throw new Error(`Ошибка VK API: ${data.error.error_msg}`);
        }
        console.log('Подробная информация о профиле:', data.response);
        return data.response;
    } catch (error) {
        console.error('Ошибка получения подробной информации о профиле:', error);
        throw error;
    }
}

/**
 * Инвалидирует Access Token (выход из аккаунта).
 * @param {string} accessToken Access Token для инвалидации.
 */
async function invalidateToken(accessToken) {
    const logoutUrl = 'https://id.vk.com/oauth2/logout';
    const params = new URLSearchParams();
    params.append('client_id', CLIENT_ID);
    params.append('access_token', accessToken);

    try {
        const response = await fetch(logoutUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Ошибка при выходе: ${errorData.error_description || response.statusText}`);
        }

        const data = await response.json();
        console.log('Выход из аккаунта:', data);
        return data;
    } catch (error) {
        console.error('Ошибка при инвалидации токена:', error);
        throw error;
    }
}

/**
 * Обрабатывает редирект после авторизации VK ID.
 */
async function handleVKIDRedirect() {
    clearMessage();
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const deviceId = urlParams.get('device_id');
    const error = urlParams.get('error');
    const errorDescription = urlParams.get('error_description');

    if (error) {
        showMessage(`Ошибка авторизации VK ID: ${errorDescription || error}`, 'error');
        window.history.replaceState({}, document.title, REDIRECT_URI);
        return;
    }

    if (!code) {
        if (sessionStorage.getItem('vk_access_token')) {
            const accessToken = sessionStorage.getItem('vk_access_token');
            try {
                const userInfo = await getUserInfo(accessToken);
                showMessage('Вы уже авторизованы.', 'success');
                showUserInfo(userInfo);
            } catch (e) {
                console.error('Ошибка при получении информации о пользователе из сохраненного токена:', e);
                showMessage('Сессия истекла или токен недействителен. Пожалуйста, войдите снова.', 'error');
                hideUserInfo();
                sessionStorage.clear();
            }
        } else {
            hideUserInfo();
        }
        return;
    }

    const storedCodeVerifier = sessionStorage.getItem('vk_code_verifier');
    const storedState = sessionStorage.getItem('vk_state');

    sessionStorage.removeItem('vk_code_verifier');
    sessionStorage.removeItem('vk_state');

    if (state !== storedState) {
        showMessage('Ошибка безопасности: state не совпадает. Пожалуйста, попробуйте войти снова.', 'error');
        window.history.replaceState({}, document.title, REDIRECT_URI);
        return;
    }

    try {
        const tokens = await exchangeCodeForTokens(code, storedCodeVerifier, deviceId);
        showMessage('Авторизация VK ID успешна! Токены получены.', 'success');

        const userInfo = await getUserInfo(tokens.access_token);
        showUserInfo(userInfo);

    } catch (e) {
        showMessage(`Ошибка при обмене кода на токены: ${e.message}`, 'error');
    } finally {
        window.history.replaceState({}, document.title, REDIRECT_URI);
    }
}

/**
 * Обрабатывает выход пользователя.
 */
async function handleLogout() {
    clearMessage();
    const accessToken = sessionStorage.getItem('vk_access_token');
    if (accessToken) {
        try {
            await invalidateToken(accessToken);
            showMessage('Вы успешно вышли из аккаунта VK ID.', 'success');
        } catch (e) {
            showMessage(`Ошибка при выходе: ${e.message}`, 'error');
        }
    } else {
        showMessage('Вы не авторизованы.', 'error');
    }
    sessionStorage.clear();
    hideUserInfo();
}

/**
 * Обрабатывает нажатие кнопки "Показать информацию о профиле".
 */
async function handleGetProfileInfo() {
    clearMessage();
    const accessToken = sessionStorage.getItem('vk_access_token');
    if (!accessToken) {
        showMessage('Ошибка: Access Token отсутствует. Пожалуйста, войдите снова.', 'error');
        return;
    }

    try {
        const profileInfo = await getAccountProfileInfo(accessToken);
        showProfileDetails(profileInfo);
        showMessage('Информация о профиле успешно получена.', 'success');
    } catch (e) {
        showMessage(`Ошибка при получении информации о профиле: ${e.message}`, 'error');
        profileDetailsDisplay.classList.add('hidden');
        profileDetailsDisplay.innerHTML = '';
    }
}

// --- Инициализация при загрузке страницы ---
document.addEventListener('DOMContentLoaded', () => {
    loginButton.addEventListener('click', initiateVKIDLogin);
    logoutButton.addEventListener('click', handleLogout);
    getProfileInfoButton.addEventListener('click', handleGetProfileInfo); // Привязываем обработчик к новой кнопке

    handleVKIDRedirect();
});
