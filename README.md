# Pépé Debug 👴💻

Helper to debug Privacy Pass in browser. Very much a quickly made website, and not thought for long term use.

## Requirements

* Node 18+ (nvm is your friend)

## Installation

```shell
npm install
```

## Run

Watch for changes on src, and open the local server in browser.

```shell
npm run start
```

## Architecture

The repository contains a frontend and a helper backend. The frontend performs most of the operation, the backend is only to circumvent some limitation of web browser development. The server provides a convenient way to serve frontend file, as well as a proxy and echo server, respectively to avoid CORS and be able to trigger server side authentication.

Frontend is in `src/client`. Backend in is `src/server`.
