// ==UserScript==
// @name         PlanningCenter YouTube Integration
// @namespace    http://tampermonkey.net/
// @version      2024-11-16
// @description  Allows you to create a YouTube stream from a PlanningCenter service plan.
// @author       Auxority
// @match        https://services.planningcenteronline.com/plans/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        GM_setValue
// @grant        GM_getValue
// ==/UserScript==

// You must give your browser access to show Popups/Redirects and Google Sign-In popups on the PlanningCenter page.

(() => {
    "use strict";

    class AuthToken {
        accessToken;
        expiresIn;
        tokenType;

        static EXPECTED_TOKEN_TYPE = "Bearer";

        constructor(
            accessToken,
            expiresIn,
            tokenType,
        ) {
            this.accessToken = accessToken;
            this.expiresIn = expiresIn;
            this.tokenType = tokenType;
        }

        getAccessToken() {
            return this.accessToken;
        }

        calculateExpirationTimestamp() {
            const now = new Date();
            const newSeconds = now.getSeconds() + this.expiresIn;
            now.setSeconds(newSeconds);
            return now.getTime();
        }

        isExpired() {
            return Date.now() > this.calculateExpirationTimestamp();
        }

        static deserialize(data) {
            try {
                AuthTokenValidator.validate(data);
            } catch (e) {
                throw new Error(`Failed to validate auth token: ${e}`);
            }

            return new AuthToken(
                data.access_token,
                data.expires_in,
                data.token_type,
            );
        }
    }

    class AuthTokenValidator {
        static validate(data) {
            if (!data) {
                throw new Error("No data provided.");
            }

            console.debug(data);

            try {
                this.validateAccessToken(data.access_token);
                this.validateExpiresIn(data.expires_in);
                this.validateTokenType(data);
            } catch (e) {
                throw new Error(`Invalid data: ${e}`);
            }
        }

        static validateAccessToken(token) {
            if (!this.isValidAccessToken(token)) {
                throw new Error("Invalid access token.");
            }
        }

        static isValidAccessToken(token) {
            return token && token.length > 0;
        }

        static validateExpiresIn(expiresIn) {
            if (!this.isValidExpiresIn(expiresIn)) {
                throw new Error("Invalid expiration time.");
            }
        }

        static isValidExpiresIn(expiresIn) {
            return expiresIn && expiresIn > 0;
        }

        static validateTokenType(data) {
            if (!this.isValidTokenType(data.token_type)) {
                throw new Error("Invalid token type.");
            }
        }

        static isValidTokenType(tokenType) {
            return tokenType && tokenType === AuthToken.EXPECTED_TOKEN_TYPE;
        }
    }

    class AuthClient {
        clientId;

        GOOGLE_AUTH_MODE = "popup";

        SCOPES = [
            "https://www.googleapis.com/auth/youtube.readonly",
            "https://www.googleapis.com/auth/youtube.upload",
        ];

        constructor(clientId) {
            this.clientId = clientId;
            this.scope = this.getScope();
        }

        fetchAuthToken() {
            return new Promise((resolve, reject) => {
                const googleClient = this.getGoogleClient(resolve, reject);
                googleClient.requestAccessToken();
            });
        }

        getGoogleClient(resolve, reject) {
            return google.accounts.oauth2.initTokenClient({
                client_id: this.clientId,
                scope: this.scope,
                ux_mode: this.GOOGLE_AUTH_MODE,
                callback: (data) => this.processTokenResponse(data, resolve, reject),
            });
        }

        processTokenResponse(data, resolve, reject) {
            try {
                const loginResponse = AuthToken.deserialize(data);
                resolve(loginResponse);
            } catch (e) {
                reject(`Could not deserialize response: ${e}`);
            }
        }

        getScope() {
            return this.SCOPES.join(this.SCOPE_SEPARATOR);
        }
    }

    class TokenService {
        ACCESS_TOKEN_KEY = "ACCESS_TOKEN";
        EXPIRATION_TIMESTAMP_KEY = "EXPIRY_TIME";

        constructor() { }

        saveLoginResponse(loginResponse) {
            this.setValue(this.ACCESS_TOKEN_KEY, loginResponse.getAccessToken());
            this.setValue(this.EXPIRATION_TIMESTAMP_KEY, loginResponse.calculateExpirationTimestamp());
        }

        isUserAuthenticated() {
            return this.getAccessToken() && !this.hasTokenExpired();
        }

        getAccessToken() {
            return this.getValue(this.ACCESS_TOKEN_KEY);
        }

        hasTokenExpired() {
            const expiryTime = this.getValue(this.EXPIRATION_TIMESTAMP_KEY);
            return !expiryTime || Date.now() > expiryTime;
        }

        setValue(key, value) {
            GM_setValue(key, value);
        }

        getValue(key) {
            return GM_getValue(key);
        }

        reset() {
            this.setValue(this.ACCESS_TOKEN_KEY, "");
            this.setValue(this.EXPIRATION_TIMESTAMP_KEY, "");
        }
    }

    class ClientIdService {
        CLIENT_ID_KEY = "CLIENT_ID";

        constructor() { }

        fetchClientId() {
            const clientId = this.getValue(this.CLIENT_ID_KEY);
            if (!clientId) {
                return this.showClientIdPrompt();
            }

            return clientId;
        }

        showClientIdPrompt() {
            const clientId = prompt("Please enter your Google OAuth client ID.");
            if (!clientId) {
                throw new Error("No client ID provided.");
            }

            this.setClientId(clientId);

            return clientId;
        }

        setClientId(clientId) {
            this.setValue(this.CLIENT_ID_KEY, clientId);
        }

        setValue(key, value) {
            GM_setValue(key, value);
        }

        getValue(key) {
            return GM_getValue(key);
        }

        reset() {
            this.setValue(this.CLIENT_ID_KEY, "");
        }
    }

    class AuthService {
        initialized = false;

        GOOGLE_AUTH_MODE = "popup";
        GSI_SCRIPT_URL = "https://accounts.google.com/gsi/client";
        REDIRECT_URI = "https://services.planningcenteronline.com";
        SCOPE_SEPARATOR = " ";

        constructor(tokenService, clientIdService) {
            this.tokenService = tokenService;
            this.clientIdService = clientIdService;
        }

        async init() {
            if (this.initialized) {
                return;
            }

            this.initialized = true;

            await this.injectGSIScript();
        }

        async injectGSIScript() {
            const script = document.createElement("script");
            script.src = this.GSI_SCRIPT_URL;
            document.head.appendChild(script);

            await new Promise((resolve) => {
                script.onload = resolve;
            });
        }

        async login() {
            if (this.tokenService.isUserAuthenticated()) {
                console.info("User is already authenticated.");
                return;
            }

            await this.authenticate();
        }

        async authenticate() {
            const client = this.createTokenClient();
            try {
                const loginResponse = await client.fetchAuthToken();
                this.tokenService.saveLoginResponse(loginResponse);
            } catch (e) {
                throw new Error(`Failed to fetch access token: ${e}`);
            }
        }

        createTokenClient() {
            const clientId = this.clientIdService.fetchClientId();

            return new AuthClient(clientId);
        }

        getAccessToken() {
            return this.tokenService.getAccessToken();
        }

        reset() {
            this.tokenService.reset();
            this.clientIdService.reset();
            this.initialized = false;
        }
    }

    class YouTubeService {
        authenticationService;

        HTTP_UNAUTHORIZED_CODE = 401;
        HTTP_FORBIDDEN_CODE = 403;

        RETRY_DELAY_MS = 2500;

        YOUTUBE_API_BASE_URL = "https://www.googleapis.com/youtube/v3";

        AUTHORIZATION_HEADER_KEY = "Authorization";

        BEARER_TOKEN_PREFIX = "Bearer";

        DUMMY_ENDPOINT = "/channels?part=snippet&mine=true";

        constructor(authenticationService) {
            this.authenticationService = authenticationService;
        }

        async init() {
            await this.authenticationService.init();
        }

        async dummyApiRequest() {
            console.info("Making dummy API request.");
            await this.executeApiRequest(this.DUMMY_ENDPOINT);
        }

        async executeApiRequest(endpoint, options) {
            const url = this.buildUrl(endpoint);

            if (!options) {
                options = this.getRequestOptions();
            }

            try {
                const res = await fetch(url, options);
                return await this.handleResponse(res, endpoint, options);
            } catch (err) {
                console.error(err);
            }
        }

        buildUrl(endpoint) {
            return `${this.YOUTUBE_API_BASE_URL}${endpoint}`;
        }

        async handleResponse(res, endpoint, options) {
            if (res.ok) {
                const data = await res.json();
                console.info(data);
                return data;
            } else if (this.isUnauthorized(res.status)) {
                await this.authenticationService.login();
                options.headers.set(this.AUTHORIZATION_HEADER_KEY, this.getBearerToken());
                await this.delay(this.RETRY_DELAY_MS);
                return await this.executeApiRequest(endpoint, options);
            }

            throw new Error("Failed to fetch YouTube data.");
        }

        delay(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        isUnauthorized(status) {
            return (
                status === this.HTTP_UNAUTHORIZED_CODE ||
                status === this.HTTP_FORBIDDEN_CODE
            );
        }

        getRequestOptions() {
            return {
                headers: this.getRequestHeaders(),
            };
        }

        getRequestHeaders() {
            const headers = new Headers();
            const bearerToken = this.getBearerToken();
            headers.set(this.AUTHORIZATION_HEADER_KEY, bearerToken);

            return headers;
        }

        getBearerToken() {
            const accessToken = this.authenticationService.getAccessToken();
            return `${this.BEARER_TOKEN_PREFIX} ${accessToken}`;
        }
    }

    (async () => {
        const tokenService = new TokenService();
        const clientIdService = new ClientIdService();
        const auth = new AuthService(tokenService, clientIdService);
        const youtubeManager = new YouTubeService(auth);

        await youtubeManager.init();

        await youtubeManager.dummyApiRequest();
    })();
})();
