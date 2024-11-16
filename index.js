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

    class SettingsStorage {
        /**
         * Loads a value from the settings storage.
         * @param {string} key
         * @returns {unknown}
         */
        static load(key) {
            return GM_getValue(key);
        }

        /**
         * Saves a value to the settings storage.
         * @param {string} key
         * @param {unknown} value
         */
        static save(key, value) {
            GM_setValue(key, value);
        }

        /**
         * Deletes a value from the settings storage.
         * @param {string} key
         * @returns {unknown}
         */
        static delete(key) {
            this.save(key, "");
        }
    }

    /**
     * Represents the response received from the Google OAuth API.
     */
    class AuthToken {
        /**
         * The access token received from the Google OAuth API.
         * @type {string} The access token.
         */
        accessToken;

        /**
         * The expiration time of the access token in seconds.
         * @type {number} The expiration time in seconds.
         */
        expiresIn;

        /**
         * The type of token received from the Google OAuth API.
         * @type {string} The token type.
         */
        tokenType;

        static EXPECTED_TOKEN_TYPE = "Bearer";

        /**
         * @param {string} accessToken
         * @param {number} expiresIn
         * @param {string} tokenType
         */
        constructor(
            accessToken,
            expiresIn,
            tokenType,
        ) {
            this.accessToken = accessToken;
            this.expiresIn = expiresIn;
            this.tokenType = tokenType;
        }

        /**
         * Deserializes the data received from the Google OAuth API into an auth token.
         * @param {object} data The data to deserialize.
         * @returns {AuthToken} The deserialized auth token.
         */
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

        /**
         * Calculates the expiration timestamp of the access token.
         * @returns {number} The expiration timestamp of the access token.
         */
        calculateExpirationTimestamp() {
            const now = new Date();
            const newSeconds = now.getSeconds() + this.expiresIn;
            now.setSeconds(newSeconds);
            return now.getTime();
        }

        getAccessToken() {
            return this.accessToken;
        }
    }

    class AuthTokenValidator {
        /**
         * Validates whether the data received from the Google OAuth API is a valid auth token.
         * @param {object} data The data to validate.
         */
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
        /**
         * The OAuth client ID used to authenticate the user.
         * @type {string}
         */
        clientId;

        /**
         * The scope of the OAuth client ID.
         * @type {string}
         */
        scope;

        GOOGLE_AUTH_MODE = "popup";

        SCOPES = [
            "https://www.googleapis.com/auth/youtube",
        ];

        constructor(clientId) {
            this.clientId = clientId;
            this.scope = this.getScope();
        }

        /**
         * Fetches an authentication token from the Google OAuth API.
         * @returns {Promise<AuthToken>}
         */
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
            SettingsStorage.save(this.ACCESS_TOKEN_KEY, loginResponse.getAccessToken());
            SettingsStorage.save(this.EXPIRATION_TIMESTAMP_KEY, loginResponse.calculateExpirationTimestamp());
        }

        isUserAuthenticated() {
            return this.getAccessToken() && !this.hasTokenExpired();
        }

        getAccessToken() {
            return SettingsStorage.load(this.ACCESS_TOKEN_KEY);
        }

        hasTokenExpired() {
            const expiryTime = SettingsStorage.load(this.EXPIRATION_TIMESTAMP_KEY);
            return !expiryTime || Date.now() > expiryTime;
        }

        reset() {
            SettingsStorage.delete(this.ACCESS_TOKEN_KEY);
            SettingsStorage.delete(this.EXPIRATION_TIMESTAMP_KEY);
        }
    }

    class ClientIdService {
        CLIENT_ID_KEY = "CLIENT_ID";

        constructor() { }

        /**
         * Retrieves the OAuth client ID from the user.
         * @returns {string} The OAuth client ID.
         */
        fetchClientId() {
            const clientId = SettingsStorage.load(this.CLIENT_ID_KEY);
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

            SettingsStorage.save(this.CLIENT_ID_KEY, clientId);

            return clientId;
        }

        reset() {
            SettingsStorage.delete(this.CLIENT_ID_KEY);
        }
    }

    class AuthService {
        /**
         * Indicates whether the authentication service has been initialized.
         * @type {boolean}
         */
        initialized = false;

        /**
         * The token service used to manage authentication tokens.
         * @type {TokenService}
         */
        tokenService;

        /**
         * The client ID service used to manage OAuth client IDs.
         * @type {ClientIdService}
         */
        clientIdService;

        GOOGLE_AUTH_MODE = "popup";

        GSI_SCRIPT_URL = "https://accounts.google.com/gsi/client";

        REDIRECT_URI = "https://services.planningcenteronline.com";

        SCOPE_SEPARATOR = " ";

        /**
         * @param {TokenService} tokenService
         * @param {ClientIdService} clientIdService
         */
        constructor(tokenService, clientIdService) {
            this.tokenService = tokenService;
            this.clientIdService = clientIdService;
        }

        /**
         * Initializes the authentication service by injecting the Google Sign-In script.
         * @returns {Promise<void>}
         */
        async init() {
            if (this.initialized) {
                return;
            }

            this.initialized = true;

            await this.injectGSIScript();
        }

        /**
         * Logs the user in using Google OAuth.
         * @returns {Promise<void>}
         */
        async login() {
            if (this.tokenService.isUserAuthenticated()) {
                console.info("User is already authenticated.");
                return;
            }

            await this.authenticate();
        }

        async injectGSIScript() {
            const script = document.createElement("script");
            script.src = this.GSI_SCRIPT_URL;
            document.head.appendChild(script);

            await new Promise((resolve) => {
                script.onload = resolve;
            });
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
            if (!clientId) {
                throw new Error("OAuth client ID is missing or invalid.");
            }

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

    class YouTubeApiService {
        /**
         * The authentication service used to authenticate the user.
         * @type {AuthService}
         */
        authenticationService;

        HTTP_UNAUTHORIZED_CODE = 401;
        HTTP_FORBIDDEN_CODE = 403;

        RETRY_DELAY_MS = 2500;

        YOUTUBE_API_BASE_URL = "https://www.googleapis.com/youtube/v3";

        AUTHORIZATION_HEADER_KEY = "Authorization";

        BEARER_TOKEN_PREFIX = "Bearer";

        /**
         * @param {AuthService} authenticationService - The authentication service used to authenticate the user.
         */
        constructor(authenticationService) {
            this.authenticationService = authenticationService;
        }

        /**
         * Executes an API request to the YouTube API.
         * @param {string} endpoint - The API endpoint to call.
         * @param {unknown} options - The options to pass to the fetch request.
         * @returns {Promise<unknown>} The response data from the API.
         */
        async executeApiRequest(endpoint, options) {
            const url = this.buildUrl(endpoint);

            if (!options) {
                options = this.getRequestOptions();
            } else if (!options.headers[this.AUTHORIZATION_HEADER_KEY]) {
                options.headers[this.AUTHORIZATION_HEADER_KEY] = this.getBearerToken();
            }

            try {
                const res = await fetch(url, options);
                return await this.handleResponse(res, endpoint, options);
            } catch (err) {
                console.error(err);
            }
        }

        async handleResponse(res, endpoint, options) {
            if (res.ok) {
                const data = await res.json();
                console.info(data);
                return data;
            } else if (this.isUnauthorized(res.status)) {
                await this.authenticationService.login();
                options.headers[this.AUTHORIZATION_HEADER_KEY] = this.getBearerToken();
                // This delay is here to prevent the API from being spammed with requests if the user is not authenticated.
                await this.delay(this.RETRY_DELAY_MS);
                return await this.executeApiRequest(endpoint, options);
            }

            throw new Error("Failed to fetch YouTube data.");
        }

        buildUrl(endpoint) {
            return `${this.YOUTUBE_API_BASE_URL}${endpoint}`;
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

    /**
     * Represents a YouTube stream that can be uploaded to YouTube.
     */
    class YouTubeStream {
        /**
         * The title of the stream.
         * @type {string}
         */
        title;

        /**
         * The description of the stream.
         * @type {string}
         */
        description;

        /**
         * The scheduled start time of the stream.
         * @type {Date}
         */
        startTime;

        /**
         * The visibility status of the stream.
         * @type {string}
         */
        visibility;

        PUBLIC_STREAM_VISIBILITY = "public";
        UNLISTED_STREAM_VISIBILITY = "unlisted";
        PRIVATE_STREAM_VISIBILITY = "private";

        /**
         * @param {string} title - The title of the stream.
         * @param {Date} startTime - The scheduled start time of the stream.
         */
        constructor(title, startTime) {
            this.title = title;
            this.startTime = startTime;
            this.visibility = this.PRIVATE_STREAM_VISIBILITY;
        }

        getTitle() {
            return this.title;
        }

        setTitle(title) {
            this.title = title;
        }

        getDescription() {
            return this.description;
        }

        setDescription(description) {
            this.description = description;
        }

        getStartTime() {
            return this.startTime;
        }

        setStartTime(startTime) {
            this.startTime = startTime;
        }

        getVisibility() {
            return this.visibility;
        }

        setVisibility(visibility) {
            this.visibility = visibility;
        }
    }

    /**
     * A service that interacts with the YouTube API to create and manage streams.
     */
    class YouTubeStreamService {
        /**
         * The YouTube API service used to interact with the YouTube API.
         * @type {YouTubeApiService}
         */
        apiService;

        DUMMY_ENDPOINT = "/channels?part=snippet&mine=true";

        CREATE_STREAM_ENDPOINT = "/liveBroadcasts?part=snippet,status";

        /**
         * @param {YouTubeApiService} apiService
         */
        constructor(apiService) {
            this.apiService = apiService;
        }

        /**
         * @deprecated
         * Just a dummy API request to test the API connection and authentication.
         */
        async dummyApiRequest() {
            console.info("Making dummy API request.");
            await this.apiService.executeApiRequest(this.DUMMY_ENDPOINT);
        }

        /**
         * Uploads a stream to YouTube.
         * @param {YouTubeStream} stream
         */
        async uploadStream(stream) {
            console.info("Creating YouTube stream.");
            await this.apiService.executeApiRequest(this.CREATE_STREAM_ENDPOINT, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    snippet: {
                        title: stream.getTitle(),
                        description: stream.getDescription(),
                        scheduledStartTime: stream.getStartTime().toISOString(),
                    },
                    status: {
                        privacyStatus: stream.getVisibility(),
                    }
                }),
            });
        }
    }

    (async () => {
        const tokenService = new TokenService();
        const clientIdService = new ClientIdService();
        const authService = new AuthService(tokenService, clientIdService);
        const apiService = new YouTubeApiService(authService);
        const youtubeStreamService = new YouTubeStreamService(apiService);

        await authService.init();

        await youtubeStreamService.dummyApiRequest();

        // const stream = new YouTubeStream("Test Stream", new Date());
        // await youtubeStreamService.uploadStream(stream);
    })();
})();
