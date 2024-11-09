// ==UserScript==
// @name         WorshipTools YouTube Integration
// @namespace    http://tampermonkey.net/
// @version      2024-11-09
// @description  Prompts the user to log in with their Google account and lists a couple of videos from their YouTube channel
// @author       Auxority
// @match        https://planning.worshiptools.com/app/account/*/service/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        GM_setValue
// @grant        GM_getValue
// ==/UserScript==

(() => {
    "use strict";

    class Authentication {
        ACCESS_TOKEN_KEY = "ACCESS_TOKEN";
        CLIENT_ID_KEY = "CLIENT_ID";
        CLIENT_SECRET_KEY = "CLIENT_SECRET";
        EXPIRY_TIME_KEY = "EXPIRY_TIME";
        REDIRECT_URI_KEY = "REDIRECT_URI";
        REFRESH_TOKEN_KEY = "REFRESH_TOKEN";

        GOOGLE_AUTH_MODE = "popup";

        GSI_SCRIPT_URL = "https://accounts.google.com/gsi/client";

        TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

        SCOPES = [
            "https://www.googleapis.com/auth/youtube.readonly",
            "https://www.googleapis.com/auth/youtube.upload",
        ];

        initialized = false;

        constructor() {
            this.setClientCredentials();
        }

        async init() {
            if (this.initialized) {
                return;
            }

            this.initialized = true;

            await this.injectGSIScript();
        }

        async injectGSIScript() {
            return new Promise((resolve) => {
                const script = document.createElement("script");
                script.src = this.GSI_SCRIPT_URL;
                script.onload = () => {
                    resolve();
                };

                document.head.appendChild(script);
            });
        }

        authenticateUser() {
            return new Promise((resolve, reject) => {
                if (!this.isTokenExpired()) {
                    console.info("User is already authenticated.");
                    resolve();
                    return;
                }

                const client = google.accounts.oauth2.initCodeClient({
                    client_id: this.clientId,
                    scope: this.getScope(),
                    ux_mode: this.GOOGLE_AUTH_MODE,
                    callback: (response) => {
                        this.fetchAccessToken(response)
                            .then(resolve)
                            .catch(reject);
                    },
                });

                client.requestCode();
            });
        }

        async fetchAccessToken(clientAuthorizationResponse) {
            try {
                const url = this.getTokenURL(clientAuthorizationResponse.code);
                const res = await fetch(url, {
                    method: "POST",
                    headers: this.getAccessTokenHeaders(),
                });
                if (!res.ok) {
                    throw new Error(
                        "Failed to fetch access token from client authorization response."
                    );
                }

                const data = await res.json();

                this.handleAccessTokenResponse(data);
            } catch (e) {
                console.error(e);
            }
        }

        getAccessTokenHeaders() {
            const headers = new Headers();
            headers.append("Content-Type", "application/x-www-form-urlencoded");

            return headers;
        }

        handleAccessTokenResponse(data) {
            if (!this.isValidAccessTokenResponse(data)) {
                throw new Error("Invalid access token response.");
            }

            this.saveAccessTokenResponse(data);
        }

        isValidAccessTokenResponse(data) {
            return data && data.access_token && data.expires_in && data.refresh_token;
        }

        saveAccessTokenResponse(data) {
            this.setValue(this.ACCESS_TOKEN_KEY, data.access_token);
            this.setValue(
                this.EXPIRY_TIME_KEY,
                this.calculateExpiryTime(data.expires_in)
            );
            this.setValue(this.REFRESH_TOKEN_KEY, data.refresh_token);
        }

        calculateExpiryTime(seconds) {
            const now = new Date();
            const newSeconds = now.getSeconds() + seconds;
            now.setSeconds(newSeconds);
            return now.getTime();
        }

        processCredentials(credentials) {
            try {
                this.validateAndSaveCredentials(credentials);
            } catch (e) {
                console.info(credentials);
                throw new Error(`Invalid OAuth file: ${e}`);
            }
        }

        validateAndSaveCredentials(oauthData) {
            if (!this.isValidOAuthData(oauthData)) {
                throw new Error("Invalid OAuth data.");
            }

            this.saveCredentials(oauthData);
        }

        saveCredentials(oauthData) {
            this.setValue(this.CLIENT_ID_KEY, oauthData.web.client_id);
            this.setValue(this.CLIENT_SECRET_KEY, oauthData.web.client_secret);
            this.setValue(this.REDIRECT_URI_KEY, oauthData.web.javascript_origins[0]);
            this.setClientCredentials();
        }

        getAccessToken() {
            return this.getValue(this.ACCESS_TOKEN_KEY);
        }

        areClientCredentialsSet() {
            return this.clientId && this.clientSecret && this.redirectUri;
        }

        setClientCredentials() {
            this.clientId = this.getValue(this.CLIENT_ID_KEY);
            this.clientSecret = this.getValue(this.CLIENT_SECRET_KEY);
            this.redirectUri = this.getValue(this.REDIRECT_URI_KEY);
        }

        isValidOAuthData(oauthData) {
            return oauthData
                && oauthData.web
                && oauthData.web.client_id
                && oauthData.web.client_secret
                && oauthData.web.javascript_origins
                && oauthData.web.javascript_origins[0];
        }

        getScope() {
            return this.SCOPES.join(" ");
        }

        isTokenExpired() {
            const expiryTime = this.getValue(this.EXPIRY_TIME_KEY);
            return !expiryTime || Date.now() > expiryTime;
        }

        getTokenURL(code) {
            const url = new URL(this.TOKEN_ENDPOINT);
            url.searchParams.append("code", code);
            url.searchParams.append("client_id", this.clientId);
            url.searchParams.append("client_secret", this.clientSecret);
            url.searchParams.append("redirect_uri", this.redirectUri);
            url.searchParams.append("grant_type", "authorization_code");

            return url.toString();
        }

        setValue(key, value) {
            GM_setValue(key, value);
        }

        getValue(key) {
            return GM_getValue(key);
        }

        reset() {
            this.setValue(this.ACCESS_TOKEN_KEY, "");
            this.setValue(this.EXPIRY_TIME_KEY, "");
            this.setValue(this.REFRESH_TOKEN_KEY, "");
            this.setValue(this.CLIENT_ID_KEY, "");
            this.setValue(this.CLIENT_SECRET_KEY, "");
            this.setValue(this.REDIRECT_URI_KEY, "");
            this.setValue(this.EXPIRY_TIME_KEY, "");
            this.initialized = false;
        }
    }

    class PopupManager {
        POPUP_ID = "upload-popup";

        OAUTH_CLIENT_URL = "https://console.cloud.google.com/apis/credentials?project=yt-stream-automation";

        showingPopup = false;

        constructor(auth) {
            this.auth = auth;
        }

        async init() {
            await this.auth.init();
        }

        async authenticate() {
            if (this.auth.areClientCredentialsSet()) {
                await this.auth.authenticateUser();
            } else {
                await this.showCredentialsPopup();
            }
        }

        async handleCredentialsUpload(event) {
            const file = event.target.files[0];
            const reader = new FileReader();
            reader.onload = this.onCredentialsRead.bind(this);
            reader.readAsText(file);
        }

        async onCredentialsRead(event) {
            const rawData = event.target.result;
            if (!rawData) {
                console.error("Failed to read file.");
                return;
            }

            try {
                const data = JSON.parse(rawData);
                this.auth.processCredentials(data);
                this.removeCredentialsPopup();
                await this.auth.authenticateUser();
            } catch (e) {
                console.error("Invalid OAuth file.");
                return;
            }
        }

        removeCredentialsPopup() {
            const popup = document.getElementById(this.POPUP_ID);
            if (popup) {
                document.body.removeChild(popup);
            }
        }

        showCredentialsPopup() {
            return new Promise((resolve) => {
                if (this.showingPopup) {
                    return;
                }

                this.showingPopup = true;

                const popup = this.createPopup();
                document.body.appendChild(popup);

                const fileInput = document.getElementById("file-input");
                fileInput.addEventListener("change", async (event) => {
                    await this.handleCredentialsUpload(event);
                    resolve();
                });
            });
        }

        createPopup() {
            const popup = document.createElement("div");
            popup.id = this.POPUP_ID;
            popup.style.position = "fixed";
            popup.style.top = "50%";
            popup.style.left = "50%";
            popup.style.transform = "translate(-50%, -50%)";
            popup.style.padding = "20px";
            popup.style.backgroundColor = "#fff";
            popup.style.borderRadius = "8px";
            popup.style.boxShadow = "0 4px 8px rgba(0, 0, 0, 0.1)";
            popup.style.maxWidth = "400px";
            popup.style.width = "100%";
            popup.style.boxSizing = "border-box";
            popup.style.textAlign = "center";

            const title = document.createElement("h2");
            title.style.color = "#333";
            title.textContent = "Upload OAuth Client";
            popup.appendChild(title);

            const link = document.createElement("a");
            link.href = this.OAUTH_CLIENT_URL;
            link.textContent = "Download the OAuth Client here";
            link.target = "_blank";
            link.style.color = "#007bff";
            link.style.textDecoration = "none";
            link.style.display = "block";
            link.style.marginTop = "5px";
            popup.appendChild(link);

            const fileInput = document.createElement("input");
            fileInput.type = "file";
            fileInput.accept = ".json";
            fileInput.id = "file-input";
            fileInput.style.display = "none";
            popup.appendChild(fileInput);

            const uploadButton = document.createElement("button");
            uploadButton.id = "upload-button";
            uploadButton.textContent = "Upload";
            uploadButton.style.padding = "10px 20px";
            uploadButton.style.marginTop = "20px";
            uploadButton.style.border = "none";
            uploadButton.style.borderRadius = "4px";
            uploadButton.style.backgroundColor = "#007bff";
            uploadButton.style.color = "#fff";
            uploadButton.style.cursor = "pointer";
            uploadButton.style.fontSize = "16px";
            uploadButton.style.transition = "background-color 0.3s";

            uploadButton.onmouseover = () => (uploadButton.style.backgroundColor = "#0056b3");
            uploadButton.onmouseout = () => (uploadButton.style.backgroundColor = "#007bff");

            popup.appendChild(uploadButton);

            this.addEventListeners(uploadButton, fileInput);

            return popup;
        }

        addEventListeners(uploadButton, fileInput) {
            uploadButton.addEventListener("click", () => fileInput.click());
        }

        getAccessToken() {
            return this.auth.getAccessToken();
        }
    }

    class YouTubeManager {
        HTTP_UNAUTHORIZED_CODE = 401;
        HTTP_FORBIDDEN_CODE = 403;

        RETRY_DELAY_MS = 2500;

        YOUTUBE_API_BASE_URL = "https://www.googleapis.com/youtube/v3";

        constructor(poupManager) {
            this.popupManager = poupManager;
        }

        async init() {
            await this.popupManager.init();
        }

        async dummyApiRequest() {
            const endpoint = "/channels?part=snippet&mine=true";
            await this.executeApiRequest(endpoint);
        }

        async executeApiRequest(endpoint, options) {
            const url = `${this.YOUTUBE_API_BASE_URL}${endpoint}`;

            if (!options) {
                options = this.getRequestOptions();
            }

            try {
                const res = await fetch(url, options);

                if (res.ok) {
                    const data = await res.json();

                    console.info(data);

                    return data;
                } else if (this.isUnauthorized(res.status)) {
                    await this.popupManager.authenticate();
                    options.headers.set("Authorization", this.getBearerToken());
                    return await this.executeApiRequest(endpoint, options);
                }

                throw new Error("Failed to fetch YouTube data.");
            } catch (err) {
                console.error(err);
            }
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
            headers.set("Authorization", bearerToken);

            return headers;
        }

        getBearerToken() {
            const accessToken = this.getAccessToken();
            return `Bearer ${accessToken}`;
        }


        getAccessToken() {
            return this.popupManager.getAccessToken();
        }
    }

    (async () => {
        const auth = new Authentication();
        const popupManager = new PopupManager(auth);
        const youtubeManager = new YouTubeManager(popupManager);

        await youtubeManager.init();

        youtubeManager.dummyApiRequest();
    })();
})();
