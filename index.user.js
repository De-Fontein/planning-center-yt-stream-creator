// ==UserScript==
// @name         PlanningCenter YouTube Integration
// @namespace    https://github.com/Auxority/planningcenter-yt-stream-creator
// @version      1.0.6
// @description  Allows you to create a YouTube stream from a PlanningCenter service plan.
// @author       Auxority
// @match        https://services.planningcenteronline.com/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @license      MIT
// @downloadURL https://github.com/Auxority/planningcenter-yt-stream-creator/raw/refs/heads/main/index.user.js
// @updateURL https://github.com/Auxority/planningcenter-yt-stream-creator/raw/refs/heads/main/index.user.js
// ==/UserScript==

"use strict";

/**
 * Represents a key-value storage for settings.
 */
class SettingsStorage {
  /**
   * Loads a value from the settings storage.
   * @param {string} key
   * @returns {unknown}
   */
  static load(key) {
    // eslint-disable-next-line no-undef
    const value = GM_getValue(key);
    console.debug(`Loaded value for key ${key}: ${value}`);
    return value;
  }

  /**
   * Saves a value to the settings storage.
   * @param {string} key
   * @param {unknown} value
   */
  static save(key, value) {
    console.debug(`Saving value for key ${key}: ${value}`);
    // eslint-disable-next-line no-undef
    GM_setValue(key, value);
  }

  /**
   * Deletes a value from the settings storage.
   * @param {string} key
   * @returns {unknown}
   */
  static delete(key) {
    console.debug(`Deleting value for key: ${key}`);
    // eslint-disable-next-line no-undef
    GM_deleteValue(key);
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
   * @param {object} data The JSON data to deserialize.
   * @returns {AuthToken} The deserialized auth token.
   */
  static deserialize(data) {
    console.debug("Deserializing auth token data.");
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
    console.debug("Calculating expiration timestamp.");
    const now = new Date();
    const newSeconds = now.getSeconds() + this.expiresIn;
    now.setSeconds(newSeconds);
    return now.getTime();
  }

  /**
   * Gets the access token.
   * @returns {string} The access token.
   */
  getAccessToken() {
    console.debug(`Getting access token: ${this.accessToken}`);
    return this.accessToken;
  }
}

/**
 * Validates the data received from the Google OAuth API.
 */
class AuthTokenValidator {
  /**
   * Validates whether the data received from the Google OAuth API is a valid auth token.
   * @param {object} data The data to validate.
   */
  static validate(data) {
    console.debug("Validating auth token data.");
    if (!data) {
      throw new Error("No data provided.");
    }

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

/**
 * Represents a client used to authenticate the user with the Google OAuth API.
 */
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
    console.debug("Fetching auth token.");
    return new Promise((resolve, reject) => {
      const googleClient = this.getGoogleClient(resolve, reject);
      googleClient.requestAccessToken();
    });
  }

  getGoogleClient(resolve, reject) {
    // eslint-disable-next-line no-undef
    return google.accounts.oauth2.initTokenClient({
      client_id: this.clientId,
      scope: this.scope,
      callback: (data) => this.processTokenResponse(data, resolve, reject),
    });
  }

  processTokenResponse(data, resolve, reject) {
    try {
      const loginResponse = AuthToken.deserialize(data);
      console.debug("Login response:", loginResponse);
      resolve(loginResponse);
    } catch (e) {
      reject(`Could not deserialize response: ${e}`);
    }
  }

  getScope() {
    return this.SCOPES.join(this.SCOPE_SEPARATOR);
  }
}

/**
 * Represents a service that manages authentication tokens for the user.
 */
class TokenService {
  ACCESS_TOKEN_KEY = "ACCESS_TOKEN";
  EXPIRATION_TIMESTAMP_KEY = "EXPIRY_TIME";

  constructor() { }

  /**
   * Saves the authentication token to the settings storage.
   * @param {AuthToken} authToken
   */
  saveAuthToken(authToken) {
    const accessToken = authToken.getAccessToken();
    const expirationTimestamp = authToken.calculateExpirationTimestamp();
    SettingsStorage.save(this.ACCESS_TOKEN_KEY, accessToken);
    SettingsStorage.save(this.EXPIRATION_TIMESTAMP_KEY, expirationTimestamp);
  }

  isUserAuthenticated() {
    console.debug("Checking if user is authenticated.");
    return this.getAccessToken() && !this.hasTokenExpired();
  }

  reset() {
    console.debug("Resetting token service.");
    SettingsStorage.delete(this.ACCESS_TOKEN_KEY);
    SettingsStorage.delete(this.EXPIRATION_TIMESTAMP_KEY);
  }

  getAccessToken() {
    return SettingsStorage.load(this.ACCESS_TOKEN_KEY);
  }

  hasTokenExpired() {
    const expiryTime = SettingsStorage.load(this.EXPIRATION_TIMESTAMP_KEY);
    return !expiryTime || Date.now() > expiryTime;
  }
}

/**
 * Represents a service that manages OAuth client IDs for the user.
 */
class ClientIdService {
  CLIENT_ID_KEY = "CLIENT_ID";

  constructor() { }

  /**
   * Retrieves the OAuth client ID from the user.
   * @returns {string} The OAuth client ID.
   */
  fetchClientId() {
    console.debug("Fetching OAuth client ID.");
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

/**
 * Represents a service that manages authentication for the user.
 */
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
    console.debug("Initializing authentication service.");
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

  logout() {
    console.info("Logging user out.");
    this.tokenService.reset();
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
    console.info("Authenticating user.");

    const client = this.createTokenClient();
    try {
      const loginResponse = await client.fetchAuthToken();
      this.tokenService.saveAuthToken(loginResponse);
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

/**
 * A service that interacts with the YouTube API to create and manage streams.
 */
class YouTubeAuthService {
  /**
   * The authentication service used to authenticate the user.
   * @type {AuthService}
   */
  authenticationService;

  HTTP_UNAUTHORIZED_CODE = 401;
  HTTP_FORBIDDEN_CODE = 403;

  RETRY_DELAY_MS = 1000;

  YOUTUBE_API_BASE_URL = "https://www.googleapis.com/youtube/v3";
  YOUTUBE_API_UPLOAD_BASE_URL = "https://www.googleapis.com/upload/youtube/v3";

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
   * @param {string} url - The API url to call.
   * @param {unknown} options - The options to pass to the fetch request.
   * @returns {Promise<unknown>} The response data from the API.
   */
  async executeRequest(url, options = {}) {
    options.headers = options.headers || new Headers();
    options.headers.set(this.AUTHORIZATION_HEADER_KEY, this.getBearerToken());
    console.debug(`Executing request to ${url}`);

    try {
      const res = await fetch(url, options);
      return await this.handleResponse(res, url, options);
    } catch (err) {
      console.error(err);
    }
  }

  async handleResponse(res, url, options) {
    console.debug(res);
    if (res.ok) {
      return await res.json();
    } else if (this.isUnauthorized(res.status)) {
      await this.authenticationService.login();
      // This delay is here to prevent the API from being spammed with requests if the user is not authenticated.
      await this.delay(this.RETRY_DELAY_MS);
      // Retry the request after re-authentication
      return await this.executeRequest(url, options);
    }

    throw new Error("Failed to fetch YouTube data.");
  }

  buildUrl(endpoint) {
    return `${this.YOUTUBE_API_BASE_URL}${endpoint}`;
  }

  buildUploadUrl(endpoint) {
    return `${this.YOUTUBE_API_UPLOAD_BASE_URL}${endpoint}`;
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
 * Represents the visibility status of a YouTube stream.
 */
class StreamVisibility {
  static PUBLIC = "public";
  static UNLISTED = "unlisted";
  static PRIVATE = "private";
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

  constructor() {
    this.title = "";
    this.startTime = new Date();
    this.visibility = StreamVisibility.PUBLIC;
  }

  /**
   * Serializes the stream data into a format that can be uploaded to YouTube.
   */
  serialize() {
    return {
      snippet: {
        title: this.getTitle(),
        description: this.getDescription(),
        scheduledStartTime: this.getStartTime().toISOString(),
      },
      status: {
        privacyStatus: this.getVisibility(),
      },
    }
  }

  getTitle() {
    return this.title;
  }

  setTitle(title) {
    this.title = title;
    return this;
  }

  getDescription() {
    return this.description;
  }

  setDescription(description) {
    this.description = description;
    return this;
  }

  getStartTime() {
    return this.startTime;
  }

  setStartTime(startTime) {
    this.startTime = startTime;
    return this;
  }

  getVisibility() {
    return this.visibility;
  }

  setVisibility(visibility) {
    this.visibility = visibility;
    return this;
  }
}

/**
 * Represents a playlist item that can be added to a YouTube playlist.
 */
class PlaylistItem {
  static RESOURCE_KIND = "youtube#video";

  /**
   * The id of the YouTube playlist.
   * @type {string}
   */
  id;

  /**
   * The id of the video to add to the playlist.
   * @type {string}
   */
  videoId;

  constructor() {
    this.id = "";
    this.videoId = "";
  }

  /**
   * Creates a new PlaylistItem from the provided playlist and video IDs.
   * @param {string} playlistId of a YouTube playlist
   * @param {string} videoId of a YouTube video
   * @returns
   */
  static fromIds(playlistId, videoId) {
    const item = new PlaylistItem();
    item.setId(playlistId);
    item.setVideoId(videoId);
    return item;
  }

  getId() {
    return this.id;
  }

  setId(id) {
    this.id = id;
  }

  getVideoId() {
    return this.videoId;
  }

  setVideoId(videoId) {
    this.videoId = videoId;
  }

  /**
   * Serializes the stream data into a format that can be used by the YouTube API.
   */
  serialize() {
    return {
      snippet: {
        playlistId: this.id,
        resourceId: {
          kind: PlaylistItem.RESOURCE_KIND,
          videoId: this.videoId
        }
      }
    }
  }
}

/**
 * A service that interacts with the YouTube API to create and manage streams.
 */
class YouTubeAPIService {
  /**
   * The YouTube API service used to interact with the YouTube API.
   * @type {YouTubeAuthService}
   */
  youtubeAuthService;

  CREATE_STREAM_ENDPOINT = "/liveBroadcasts?part=snippet,status";

  ADD_TO_PLAYLIST_ENDPOINT = "/playlistItems?part=snippet";

  ADD_THUMBNAIL_ENDPOINT = "/thumbnails/set";

  /**
   * @param {YouTubeAuthService} youtubeAuthService
   */
  constructor(youtubeAuthService) {
    this.youtubeAuthService = youtubeAuthService;
  }

  /**
   * Adds a stream to a playlist using its video id.
   * @param {PlaylistItem} playlistItem item to add to the playlist
   */
  async addToPlaylist(playlistItem) {
    const headers = this.youtubeAuthService.getRequestHeaders();
    headers.set("Content-Type", "application/json");

    const requestData = playlistItem.serialize();

    const apiUrl = this.youtubeAuthService.buildUrl(this.ADD_TO_PLAYLIST_ENDPOINT);
    const json = await this.youtubeAuthService.executeRequest(apiUrl, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(requestData),
    });

    console.debug("Playlist item added:", json);
  }

  /**
   * Adds a thumbnail to a video using PlanningCenter thumbnail url.
   * @param {string} videoId of the youtube video;
   * @param {string} url of the thumbnail image;
   * @param {string} contentType of the image;
   */
  async addThumbnail(videoId, url, contentType) {
    const headers = this.youtubeAuthService.getRequestHeaders();
    headers.set("Content-Type", contentType);

    const file_response = await fetch(url);
    const blob = await file_response.blob();

    try {
      const apiUrl = `${this.youtubeAuthService.buildUploadUrl(this.ADD_THUMBNAIL_ENDPOINT)}?videoId=${videoId}`;
      const json = await this.youtubeAuthService.executeRequest(apiUrl, {
        method: "POST",
        headers: headers,
        body: blob,
      });

      console.debug("Thumbnail added:", json);
    } catch (error) {
      throw new Error(`Failed to upload thumbnail: ${error}`);
    }
  }

  /**
   * Uploads a stream to YouTube.
   * @param {YouTubeStream} stream
   * @returns {Promise<string>} video id of the stream.
   */
  async uploadStream(stream) {
    const headers = this.youtubeAuthService.getRequestHeaders();
    headers.set("Content-Type", "application/json");

    const requestData = stream.serialize();

    const apiUrl = this.youtubeAuthService.buildUrl(this.CREATE_STREAM_ENDPOINT);
    const json = await this.youtubeAuthService.executeRequest(apiUrl, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(requestData),
    });

    console.debug("Stream created:", json);

    return json.id;
  }
}

class PlanningCenterService {
  static API_BASE_URL = "https://api.planningcenteronline.com/services/v2";
  static SONGBOOK_TAG_GROUP_ID = "2559219";

  constructor() { }

  /**
   * Gets a plan from PlanningCenter by its ID.
   * @param {number} id the ID of the plan
   * @returns {Promise<object>} the plan data
   */
  async fetchPlan(id) {
    const url = this.buildPlanUrl(id);

    try {
      return await this.fetchJson(url);
    } catch (error) {
      throw new Error(`Failed to fetch plan: ${error}`);
    }
  }

  /**
   * Gets the notes in a plan from PlanningCenter by its ID.
   * @param {number} planId the ID of the plan
   * @returns {Promise<object>} the notes in the plan
   */
  async fetchNotes(planId) {
    const url = `${this.buildPlanUrl(planId)}/notes`;

    try {
      return await this.fetchJson(url);
    } catch (error) {
      throw new Error(`Failed to fetch notes: ${error}`);
    }
  }

  /**
   * Gets the songs in a plan from PlanningCenter by its ID.
   * @param {number[]} songIds the IDs of the songs
   * @returns {Promise<object>} the songs in the plan
   */
  async fetchSongs(songIds) {
    try {
      const promises = songIds.map((songId) => this.fetchSong(songId));
      return await Promise.all(promises);
    } catch (error) {
      throw new Error(`Failed to fetch songs: ${error}`);
    }
  }

  async fetchSong(songId) {
    const url = `${PlanningCenterService.API_BASE_URL}/songs/${songId}`;

    try {
      return await this.fetchJson(url);
    } catch (error) {
      throw new Error(`Failed to fetch song: ${error}`);
    }
  }

  /**
   * Fetches all tags for the given song IDs.
   * @param {number[]} songIds the IDs of the songs
   * @returns {Promise<object[]>} the tags for the songs
   */
  async fetchAllTags(songIds) {
    try {
      const promises = songIds.map((songId) => this.fetchTags(songId));
      return await Promise.all(promises);
    } catch (error) {
      throw new Error(`Failed to fetch song tags: ${error}`);
    }
  }

  async fetchTags(songId) {
    const url = `${PlanningCenterService.API_BASE_URL}/songs/${songId}/tags`;

    try {
      return await this.fetchJson(url);
    } catch (error) {
      // Possible to not throw error when tags fail, but keep going without tags
      // throw new Error(`Failed to fetch song tags: ${error}`);
      return [];
    }
  }

  /**
   * Fetches the thumbnail for the video/stream with the given planId.
   * @param {number} planId the ID of the plan.
   * @returns {Promise<object>} the attributes of 1 thumbnail or null.
   */
  async fetchThumbnail(planId) {
    try {
      const attachments = await this.fetchAttachments(planId);
      const attachmentTypeIds = await this.getUniqueAttachmentTypeIds(attachments);

      const attachmentTypes = await this.fetchAttachmentTypes(attachmentTypeIds);
      const attachmentTypeMap = new Map((attachmentTypes ?? []).map(at => [at.data?.id, at.data?.attributes?.name]));

      const attachmentsWithTypes = await this.getValidAttachmentsWithTypes(attachments, attachmentTypeMap);
      if (!attachmentsWithTypes.data.length) {
        console.debug(`Error fetching thumbnail (data length): ${error}`);
        return null;
      }

      return attachmentsWithTypes.data[0].attributes;
    } catch (error) {
      console.debug(`Error fetching thumbnail: ${error}`);
      return null;
    }
  }

  async fetchAttachments(planId) {
    const url = `${this.buildPlanUrl(planId)}/attachments`;

    try {
      return await this.fetchJson(url);
    } catch (error) {
      // Possible to not throw error when this fails, keep going without thumbnail.
      // throw new Error(`Failed to fetch attachments: ${error}`);
      return null;
    }
  }

  async getUniqueAttachmentTypeIds(attachments) {
    try {
      return [...new Set(attachments.data.flatMap(item =>
        item?.relationships?.attachment_types?.data?.map(at => at.id) || []
      ))];
    } catch (error) {
      throw new Error(`Failed to get unique attachment type ids from attachments: ${error}`);
    }
  }

  async fetchAttachmentTypes(typeIds) {
    try {
      const promises = typeIds.map((typeId) => this.fetchAttachmentType(typeId));
      return await Promise.all(promises);
    } catch (error) {
      // Possible to not throw error when this fails, keep going without thumbnail.
      // throw new Error(`Failed to fetch attachment types: ${error}`);
      return [];
    }
  }

  async fetchAttachmentType(typeId) {
    const url = `${PlanningCenterService.API_BASE_URL}/attachment_types/${typeId}`;

    try {
      return await this.fetchJson(url);
    } catch (error) {
      throw new Error(`Failed to fetch attachment type: ${error}`);
    }
  }

  async getValidAttachmentsWithTypes(attachments, attachmentTypeMap) {
    try {
      let atData = attachments.data.map(item => {
        const ids = item?.relationships?.attachment_types?.data?.map(at => at.id) || [];
        const names = ids.map(id => attachmentTypeMap.get(id)).filter(Boolean);

        return {
          ...item,
          attributes: {
              ...item.attributes,
            attachment_types: names
          }
        };
      });

      atData = await this.isValidThumbnail(atData);

      return {
        ...attachments,
        data: atData
      };
    } catch (error) {
      throw new Error(`Failed to combine types with the attachments: ${error}`);
    }
  }

  async isValidThumbnail(atData) {
    try {
      return atData.filter(item => {
        const types = item.attributes?.attachment_types ?? [];
        const isThumbnail = types.includes(StreamManager.THUMBNAIL_ATTACHMENT_NAME);
        const isImage = item.attributes?.filetype === StreamManager.THUMBNAIL_FILE_TYPE;
        const withinSizeLimit = item.attributes?.file_size <= StreamManager.THUMBNAIL_MAX_SIZE_BYTES;
        return isThumbnail && isImage && withinSizeLimit;
      });
    } catch (error) {
      throw new Error(`Failed to validate thumbnail from atData: ${error}`);
    }
  }

  async fetchItems(planId) {
    const url = `${this.buildPlanUrl(planId)}/items`;

    try {
      return await this.fetchAllJsonData(url);
    } catch (error) {
      throw new Error(`Failed to fetch items: ${error}`);
    }
  }

  async fetchAllJsonData(url) {
    const allData = [];
    let nextUrl = url;

    while (nextUrl) {
      const json = await this.fetchJson(nextUrl);
      const data = json.data;
      if (data) {
        allData.push(...data);
      }

      nextUrl = json.links?.next;
    }

    return allData;
  }

  async fetchJson(url) {
    const res = await fetch(url, { credentials: "include" });
    return await res.json();
  }

  buildPlanUrl(id) {
    return `${PlanningCenterService.API_BASE_URL}/plans/${id}`;
  }
}

/**
 * Handles everything related to the DOM.
 */
class DomService {
  static ORIGINAL_BUTTON_SELECTOR = `button[aria-label="Share"]`;
  static STREAM_BUTTON_ID = "yt-stream-button";

  constructor() { }

  /**
   * Creates a button that allows the user to create a stream.
   * @returns {Promise<HTMLButtonElement>}
   */
  async createStreamButton() {
    console.debug("Looking for original button to clone...");

    const originalButton = await this.queryElement(DomService.ORIGINAL_BUTTON_SELECTOR);

    if (this.streamButtonExists()) {
      console.debug("Stream button already exists!");
      return;
    }

    console.debug("Creating stream button.");

    const youtubeButton = originalButton.cloneNode(true);
    youtubeButton.id = DomService.STREAM_BUTTON_ID;
    youtubeButton.innerText = "New Stream";
    youtubeButton.setAttribute("aria-label", "New Stream");

    originalButton.parentNode.prepend(youtubeButton);

    return youtubeButton;
  }

  /**
   * Checks whether the current page is a service plan page.
   * @returns {boolean}
   */
  isPlanPage() {
    return window.location.pathname.startsWith(App.PLANS_PAGE_PREFIX);
  }

  /**
   * Checks whether the stream button already exists on the page
   * @returns {boolean}
   */
  streamButtonExists() {
    return document.querySelector(`#${DomService.STREAM_BUTTON_ID}`) !== null;
  }

  /**
   * Gets the ID of the plan from the URL.
   * @returns {number}
   */
  getPlanId() {
    const rawId = window.location.pathname.split("/").pop();
    return Number(rawId);
  }

  /**
   * Shows a preview of the stream that will be created, and allows the user to confirm the stream creation.
   * @param {YouTubeStream} stream - The stream to preview.
   */
  confirmStreamCreation(stream) {
    return confirm(`Do you want to create a stream titled "${stream.getTitle()}"?`);
  }

  queryElement(selector) {
    return new Promise((resolve) => {
      const element = document.querySelector(selector);
      if (element) {
        resolve(element);
        return;
      }

      const observer = new MutationObserver(() => {
        const newElement = document.querySelector(selector);
        if (newElement) {
          observer.disconnect();
          resolve(newElement);
        }
      });

      observer.observe(document.body, {
        childList: true,
        subtree: true,
      });
    });
  }
}

class DateFormatter {
  static LOCALE_LANGUAGE = "nl-NL";

  static YEAR_FORMAT = "numeric";
  static MONTH_FORMAT = "2-digit";
  static DAY_FORMAT = "2-digit";

  static format(date) {
    const options = {
      year: DateFormatter.YEAR_FORMAT,
      month: DateFormatter.MONTH_FORMAT,
      day: DateFormatter.DAY_FORMAT,
    };

    return date.toLocaleString(DateFormatter.LOCALE_LANGUAGE, options);
  }
}

/**
 * Manages the streams that are created and uploaded to YouTube.
 */
class StreamManager {
  // TODO: Make all of these static constants configurable.
  static ALL_PLAYLIST_IDS = [
    "PL-sPk2tbAU2MrOKm0AlBSqSVeZsK1xanp", // Standard Playlist
    "PL-sPk2tbAU2PRg6JjO47vYbI3h4oLRLYf", // All Preachers Playlist
    "PL-sPk2tbAU2Pa6pSNB3YDQJOFoJptZt5k" // Current Season Playlist
  ];
  static PREACHER_PLAYLIST_IDS = {
    "leander janse": "PL-sPk2tbAU2NcW17OnFlSh-hO1JjpT9Fp",
    "mathijs page": "PL-sPk2tbAU2MA4dGc7v2d7zdbULt3axYh",
    "paul van 't veer": "PL-sPk2tbAU2Pg6YGd6suZ0Brb9-avYI2z"
  };

  static normalizeStr(s) {
    return (s || "")
    .trim()
    .toLowerCase()
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "");
  }

  static PREACHER_NOTE_CATEGORY = "Spreker";
  static THEME_NOTE_CATEGORY = "Thema";
  static DESCRIPTION_TEMPLATE = [
    "De diensten beginnen elke zondag om 10:00 uur.",
    "",
    "Liederen",
    "{SONGS}",
    "",
    "Informatie",
    "Wil je meer weten over kerk De Fontein of in contact komen met ons? Bezoek dan onze website https://www.kerkdefontein.nl/",
    "Liever mailen? Dat kan via info@kerkdefontein.nl",
  ].join("\n");

  static THUMBNAIL_ATTACHMENT_NAME = "Thumbnail";
  static THUMBNAIL_FILE_TYPE = "image";
  static THUMBNAIL_MAX_SIZE_BYTES = 2 * 1024 * 1024;

  /**
   * The YouTube stream service used to interact with the YouTube API.
   * @type {YouTubeAPIService}
   */
  youtubeApiService;

  /**
   * The PlanningCenter service used to interact with the PlanningCenter API.
   * @type {PlanningCenterService}
   */
  planningCenterService;

  /**
   * @param {DomService} domService
   */
  domService;

  /**
   * @param {YouTubeAPIService} youtubeApiService
   * @param {PlanningCenterService} planningCenterService
   * @param {DomService} domService
   */
  constructor(youtubeApiService, planningCenterService, domService) {
    this.youtubeApiService = youtubeApiService;
    this.planningCenterService = planningCenterService;
    this.domService = domService;
  }

  /**
   * Initializes the stream manager.
   */
  async init() {
    console.debug("Initializing stream manager.");

    const planId = this.domService.getPlanId();
    const streamButton = await this.domService.createStreamButton();

    streamButton?.addEventListener("click", () => this.onStreamButtonClick(planId));
  }

  /**
   * Creates a stream and uploads it to YouTube.
   * @param {number} planId - The ID of the plan to create a stream for.
   */
  async onStreamButtonClick(planId) {
    console.debug("Stream button clicked.");

    const stream = await this.getStreamFromPlanId(planId);

    const confirmed = this.domService.confirmStreamCreation(stream);
    if (confirmed) {
      const videoId = await this.createStream(stream);
      console.debug(`Livestream video id: ${videoId}`);

      // Get the preacher key to add automatically to correct preacher playlist.
      const preacherRaw = (stream?.title || "").split("|").map(p => p.trim())[1] || "";
      const preacherKey = StreamManager.normalizeStr(preacherRaw);

      const playlistIds = new Set(StreamManager.ALL_PLAYLIST_IDS);
      const preacherPid = StreamManager.PREACHER_PLAYLIST_IDS[preacherKey];
      if (preacherPid) {
        playlistIds.add(preacherPid);
      }

      const promises = [...playlistIds].map(id => this.addToPlaylist(id, videoId));
      await Promise.all(promises);
      console.info("Stream added to playlist(s).");

      await this.addThumbnail(planId, videoId);

      alert("Stream created!");
    } else {
      alert("Stream creation cancelled.");
    }
  }

  /**
   * Adds a YouTube stream to a playlist using the provided details.
   * @param {string} id of the playlist
   * @param {string} videoId of the video to add to the playlist
   * @returns {Promise<void>}
   */
  async addToPlaylist(id, videoId) {
    console.debug("Adding stream to playlist.");
    const playlistItem = PlaylistItem.fromIds(id, videoId);
    await this.youtubeApiService.addToPlaylist(playlistItem);
    console.debug("Stream added to playlist.");
  }

  /**
   * Tries to add a thumbnail to the stream using the provided details.
   * @param {string} videoId to add the thumbnail.
   * @param {string} thumbnailUrl in PlanningCenter.
   * @param {string} contentType of the thumbnail.
   * @param {string} label of which url it is (Main or Backup).
   * @returns {Promise<void>}
   */
  async tryAddThumbnail(videoId, thumbnailUrl, contentType, label) {
    if (!thumbnailUrl) {
      console.debug(`${label} thumbnail not available, skipping...`);
      return false;
    }

    try {
      await this.youtubeApiService.addThumbnail(videoId, thumbnailUrl, contentType);
      console.debug(`${label} thumbnail added to video`);
      return true;
    } catch (error) {
      console.debug(`${label} thumbnail error: ${error}`);
      return false;
    }
  }

  /**
   * Gets thumbnail from PlanningCenter and tries main (or backup) thumbnail to add to video.
   * @param {string} planId of the PlanningCenter plan
   * @param {string} videoId of the video to add the thumbnail
   * @returns {Promise<void>}
   */
  async addThumbnail(planId, videoId) {
    console.debug("Adding thumbnail to video.");
    const thumbnail = await this.planningCenterService.fetchThumbnail(planId);
    if (thumbnail) {
      const fileUrl = thumbnail.url;
      const backupFileUrl = thumbnail.thumbnail_url;
      const contentType = thumbnail.content_type;

      const success = await this.tryAddThumbnail(videoId, fileUrl, contentType, "Main");
      if (!success) {
        await this.tryAddThumbnail(videoId, backupFileUrl, contentType, "Backup");
      }

      console.info("Stream thumbnail added.");
    } else {
      console.debug("Stopping and keeping standard thumbnail");
    }
  }

  async getStreamFromPlanId(planId) {
    const planData = await this.planningCenterService.fetchPlan(planId);
    console.debug("Plan data:", planData);

    const notes = await this.planningCenterService.fetchNotes(planId);
    console.debug("Notes:", notes);

    const description = await this.getDescription(planId);
    console.debug("Description:", description);

    const title = this.getTitle(planData, notes);
    console.debug("Title:", title);

    const date = this.getDate(planData);

    return new YouTubeStream()
      .setTitle(title)
      .setDescription(description)
      .setStartTime(date);
  }

  getTitle(planData, notes) {
    const date = this.getFormattedDate(planData);
    console.debug("Date:", date);

    const preacher = this.getPreacher(notes);
    console.debug("Preacher:", preacher);

    const theme = this.getTheme(notes);
    console.debug("Theme:", theme);

    return `${theme} | ${preacher} | ${date}`;
  }

  getFormattedDate(planData) {
    const rawDate = this.getDate(planData);
    return DateFormatter.format(rawDate);
  }

  getDate(planData) {
    const now = new Date();

    console.debug("Date attributes:", planData.data.attributes);

    // PlanningCenter stores dates in UTC, so we need to convert it to local time to match the date & time with the UI.
    const utcDate = new Date(planData.data.attributes.sort_date);

    // The timezone offset is in minutes, so we need to convert it to milliseconds.
    const localOffsetMs = utcDate.getTimezoneOffset() * 60 * 1000;
    let plannedDate = new Date(utcDate.getTime() + localOffsetMs);

    // If the planned date is in the past, we need to schedule the stream for the future.
    if (plannedDate < now) {
      // add 5 minutes to the current time to prevent scheduling a stream in the past.
      plannedDate = new Date(now.getTime() + 5 * 60 * 1000);
    }

    console.debug(`Planned date: ${plannedDate.toISOString()}`);

    return plannedDate;
  }

  async getDescription(planId) {
    const items = await this.planningCenterService.fetchItems(planId);
    const songIds = items.filter((item) => item.relationships.song.data !== null).map((item) => item.relationships.song.data.id);

    const songs = await this.planningCenterService.fetchSongs(songIds);
    const allTags = await this.planningCenterService.fetchAllTags(songIds);

    console.debug("Tags:", allTags);

    songs.forEach((song, index) => {
      const tagData = allTags[index]?.data || [];
      const target = tagData.find(tag => String(tag.relationships?.tag_group?.data?.id) === PlanningCenterService.SONGBOOK_TAG_GROUP_ID);
      song.tag = target ? target.attributes.name : "";
    });

    console.debug("Songs:", songs);

    const songLines = songs.map(song => this.formatSongLine(song));

    return StreamManager.DESCRIPTION_TEMPLATE.replace("{SONGS}", songLines.join("\n"));
  }

  /**
   * Formats a single song entry for the YouTube description.
   * @param {object} song PlanningCenter song object (augmented with song.tag)
   * @returns {string}
   */
  formatSongLine(song) {
    const rawTitle = (song.data?.attributes?.title || "").trim();
    const rawTag = (song.tag || "").trim();
    const numMatch = rawTitle.match(/\((\d+)\)\s*$/);
    const songNumber = numMatch ? Number(numMatch[1]) : null;
    const baseTitle = rawTitle.replace(/\s*\(\d+\)\s*$/, "").trim();
    const tagLower = rawTag.toLowerCase();

    // Skip tag prefix only when tag is "overig" or empty
    if (!rawTag || tagLower === "overig") {
      return baseTitle;
    }

    // Always include the song number (after the tag) when one is found
    if (songNumber) {
      return `${rawTag} ${songNumber} - ${baseTitle}`;
    }

    return `${rawTag} - ${baseTitle}`;
  }

  getPreacher(notes) {
    return notes.data.filter((note) => note.attributes.category_name === StreamManager.PREACHER_NOTE_CATEGORY)[0].attributes.content;
  }

  getTheme(notes) {
    return notes.data.filter((note) => note.attributes.category_name === StreamManager.THEME_NOTE_CATEGORY)[0].attributes.content;
  }

  /**
   * Creates a new YouTube stream using the provided details.
   * @param {YouTubeStream} stream required details of a new YouTube stream.
   * @returns {Promise<string>} video id of the stream.
   */
  async createStream(stream) {
    console.info("Creating stream.", stream);
    const videoId = await this.youtubeApiService.uploadStream(stream);
    console.info("Stream uploaded.");
    return videoId;
  }
}

/**
 * Used to detect URL changes in Single Page Applications
 */
class URLWatcher {
  /**
   * The function to call when a URL change is detected.
   * @type {Function} the function to call
   */
  callback;

  /**
   * The last URL before a change in URL was detected.
   * Used to compare against the current URL.
   * @type {string} the last known URL of the window
   */
  lastUrl;

  /**
   * Used to check for changes in the URL.
   * @type {MutationObserver} used to detect changes in the DOM
   */
  observer;

  static INTERVAL_DELAY_IN_MS = 500;

  static OBSERVER_CONFIG = {
    subtree: true,
    childList: true,
  };

  constructor(callback) {
    this.callback = callback;
    this.lastUrl = location.href;
  }

  init() {
    setInterval(() => this.callback(), URLWatcher.INTERVAL_DELAY_IN_MS);
  }

  hookHistoryMethod(method) {
    const original = history[method];
    history[method] = (...args) => {
      original.apply(history, args);
      window.dispatchEvent(new Event("urlChange"));
    };
  }

  disconnect() {
    this.disconnectObserver();
    window.removeEventListener("popstate", this.onUrlChange);
    window.removeEventListener("urlChange", this.onUrlChange);
  }

  disconnectObserver() {
    if (this.observer) {
      this.observer.disconnect();
    }
  }
}

class App {
  authService;
  streamManager;
  watcher;

  static PLANS_PAGE_PREFIX = "/plans/";

  constructor() {
    const tokenService = new TokenService();
    const clientIdService = new ClientIdService();
    this.authService = new AuthService(tokenService, clientIdService);
    const youtubeAuthService = new YouTubeAuthService(this.authService);
    const youtubeApiService = new YouTubeAPIService(youtubeAuthService);
    this.domService = new DomService(youtubeApiService);
    const planningCenterService = new PlanningCenterService();
    this.streamManager = new StreamManager(youtubeApiService, planningCenterService, this.domService);
    this.watcher = new URLWatcher(() => this.update());
  }

  /**
   * Creates a new instance of the application.
   */
  async init() {
    await this.authService.init();
    this.watcher.init();
  }

  /**
   * Runs the application.
   */
  async run() {
    await this.streamManager.init();
  }

  /**
   * Checks whether the application should run and runs it if it should.
   */
  update() {
    if (this.shouldRun()) {
      this.run();
    }
  }

  /**
   * Checks whether the application should run.
   * @returns {boolean}
   */
  shouldRun() {
    return this.domService.isPlanPage() && !this.domService.streamButtonExists();
  }
}

const app = new App();
app.init();
