// Local server to improve web development on port 3000
// GET serves content from `dist`, which builds the frontend
// POST has two targets
// POST /echo <body> returns the request body with the request headers
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
  if (req.url === "/") {
    req.url = "/index.html";
  }
  const requestPath = path.normalize(req.url?.slice(1) ?? "");
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
  let requestBody = "";
  req.on("data", (chunk) => {
    requestBody += chunk.toString();
  });

  req.on("end", () => {
    res.writeHead(200, req.headers);

    res.end(requestBody);
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
      return handleDist(req, res);
    case "POST": {
      if (req.url?.startsWith("/echo")) {
        return handleEcho(req, res);
      }
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
