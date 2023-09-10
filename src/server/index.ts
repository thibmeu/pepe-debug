// Local server to improve web development on port 3000
// GET serves content from `dist`, which builds the frontend
// POST has two targets
// POST /echo-authentication returns the request WWW-Authenticate header if passed. If Authorization header is found, returns it in the response body
// POST /proxy?target=<url> query the target url with the request headers and returns the response unmodified
import fs from "fs";
import http from "http";
import path from "path";

// ts-node would complain if the following type was not declared "error TS2304: Cannot find name 'fetch'"
// https://github.com/DefinitelyTyped/DefinitelyTyped/issues/60924
declare global {
  const fetch: typeof import("undici").fetch;
}

function getCurrentTimeFormatted() {
  const now = new Date();

  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const seconds = String(now.getSeconds()).padStart(2, "0");

  const formattedTime = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  return formattedTime;
}

const handleDist = (req: http.IncomingMessage, res: http.ServerResponse) => {
  let pathname = req.url?.split("?")[0] ?? "/";
  if (pathname === "/") {
    pathname = "/index.html";
  }
  const requestPath = path.normalize(pathname.slice(1) ?? "");
  const filePath = path.join(__dirname, "../../dist", requestPath);

  if (!fs.existsSync(filePath)) {
    return handleNotFound(req, res);
  }

  let contentType = "text/plain";
  switch (path.extname(filePath)) {
    case ".html":
      contentType = "text/html";
      break;
    case ".css":
      contentType = "text/css";
      break;
    case ".js":
      contentType = "application/javascript";
      break;
    default:
      break;
  }

  const data = fs.readFileSync(filePath);

  res.writeHead(200, { "Content-Type": contentType });
  res.end(data);
};

const handleEcho = (req: http.IncomingMessage, res: http.ServerResponse) => {
  req.on("data", (chunk) => undefined);

  req.on("end", () => {
    const status = req.headers["authorization"] ? 200 : 401;
    const headers: http.OutgoingHttpHeaders = {
      "content-type": "text/plain; charset=utf-8",
      date: new Date().toUTCString(),
    };
    const authenticationRequest = req.headers["www-authenticate"];
    if (authenticationRequest) {
      console.log(
        `[${getCurrentTimeFormatted()}]\tWWW-Authenticate ${authenticationRequest}`,
      );
      headers["www-authenticate"] = authenticationRequest;
    } else {
      console.log(
        `[${getCurrentTimeFormatted()}]\tAuthorization ${
          req.headers.authorization
        }`,
      );
    }

    res.writeHead(status, headers);

    const response = status === 200 ? req.headers.authorization : "J";
    res.end(response);
  });
};

const handleProxy = (req: http.IncomingMessage, res: http.ServerResponse) => {
  req.on("data", () => undefined);
  req.on("end", async () => {
    const url = new URL(`http://test.test${req.url}`);
    const targetUrl = url.searchParams.get("target");

    if (!targetUrl) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Missing `target` URL in query parameters");
      return;
    }

    delete req.headers["host"];
    delete req.headers["origin"];
    delete req.headers["content-length"];

    let headers = Object.entries(req.headers).filter(
      (h) => h !== undefined,
    ) as [string, string][];
    const response = await fetch(targetUrl, {
      headers,
    });
    const responseData = await response.text();

    res.writeHead(response.status, headers);
    res.end(responseData);
  });
};

const handleNotFound = (
  _req: http.IncomingMessage,
  res: http.ServerResponse,
) => {
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("404 Not Found\n");
};

const server = http.createServer((req, res) => {
  console.log(`[${getCurrentTimeFormatted()}]\t${req.method}\t${req.url}`);
  switch (req.method) {
    case "GET":
      if (req.url?.startsWith("/echo-authentication")) {
        return handleEcho(req, res);
      }
      return handleDist(req, res);
    case "POST": {
      if (req.url?.startsWith("/proxy")) {
        return handleProxy(req, res);
      }
      return handleNotFound(req, res);
    }
    default:
      return handleNotFound(req, res);
  }
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(
    `[${getCurrentTimeFormatted()}]\tPépé Debug server is running on port ${PORT}`,
  );
});
