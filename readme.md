# PlanningCenter YouTube Integration

I wrote this script for our tech team at church, so they can easily create a YouTube stream from a service in PlanningCenter.


## Usage

### Installing a userscript manager

I recommend that you use [Violentmonkey](https://violentmonkey.github.io/get-it/), an open-source and privacy-focused userscript manager for your browser.

<details>

*[Greasemonkey](https://www.greasespot.net/) is a great alternative option if you are using Firefox. But you will have to modify some code related to the `@grant` annotations like `GM_setValue`.*

*Tampermonkey is no longer open-source, so that's why I cannot recommend it.*

</details>

### Installing the userscript

1. Visit [https://greasyfork.org/en/scripts/530744-planningcenter-youtube-integration](https://greasyfork.org/en/scripts/530744-planningcenter-youtube-integration)
2. Press `Install this script`
3. A new page should open, click `Install`
4. Done

### Configuring Google Cloud Console

1. Create a Google Cloud project - see [https://developers.google.com/workspace/guides/create-project](https://developers.google.com/workspace/guides/create-project) for a tutorial.
2. Follow step 2 and 3 from [https://developers.google.com/youtube/v3/getting-started](https://developers.google.com/youtube/v3/getting-started) - make sure to create OAuth 2.0 credentials.
3. Done

### First time 
1. Open a Plan in Planning Center
2. Copy the `Client ID` value from the OAuth 2.0 credentials from Google Cloud.
3. Press the "New Stream" button.
4. Paste your copied `Client ID` when asked.

<details>

We use notes in our services called `Spreker` and `Thema`.

The `Spreker` (Preacher) note is used to set the name of the preacher in the livestream title.

The `Thema` (Theme) note is used to set as the prefix of the stream title.

The date is added as a suffix to the theme and preacher name.

If you want to customize the names of these notes, you can modify the `StreamManager` class in the code. This class also contains the description template, which you will want to modify.

</details>
