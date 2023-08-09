import * as privacypass from "@cloudflare/privacypass-ts";

const u8ToB64 = (u: Uint8Array): string => btoa(String.fromCharCode(...u));

const b64Tou8 = (b: string): Uint8Array =>
  Uint8Array.from(atob(b), (c) => c.charCodeAt(0));

const b64ToB64URL = (s: string): string =>
  s.replace(/\+/g, "-").replace(/\//g, "_");

const b64URLtoB64 = (s: string): string =>
  s.replace(/-/g, "+").replace(/_/g, "/");

const LOCAL_URL = window.origin;
const ECHO_URL = `${LOCAL_URL}/echo`;
const PROXY_URL = `${LOCAL_URL}/proxy`;

class TransformResult {
  private _string: string;
  private _fill: string[];

  constructor(s: string, ...fill: string[]) {
    this._string = s;
    this._fill = fill ?? [];
  }

  toString() {
    return this._string;
  }
  toFill() {
    return this._fill;
  }
}

const isLocalServerAvailable = async (): Promise<boolean> => {
  const response = await fetch(ECHO_URL, {
    method: "POST",
    headers: { test: "1" },
  });
  return response.headers["test"] === "1";
};

const proxyFetch = (url: string, init?: RequestInit) => {
  const request = new URL(PROXY_URL);
  request.searchParams.append("target", url);

  const params = init ?? {};
  params.method = "POST";

  return fetch(request, params);
};

const checkExtension = async (id: string): Promise<boolean> => {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(id, { message: "state" }, (response) =>
        resolve(response.support.includes("pat")),
      );
    } catch (_) {
      resolve(false);
    }
  });
};

const parsePublicKey = async (pk: string): Promise<CryptoKey> => {
  const pkEnc = b64Tou8(b64URLtoB64(pk));
  const spkiEncoded = privacypass.util.convertRSASSAPSSToEnc(pkEnc);
  return crypto.subtle.importKey(
    "spki",
    spkiEncoded,
    { name: "RSA-PSS", hash: "SHA-384" },
    true,
    ["verify"],
  );
};

const validatePublicKey = async (pk: string): Promise<TransformResult> => {
  try {
    const _ = await parsePublicKey(pk);
    return new TransformResult("Valid");
  } catch (e) {
    return new TransformResult(e.message);
  }
};

const fetchIssuers = async (url: string): Promise<TransformResult> => {
  let response: Response;
  try {
    response = await proxyFetch(url);
  } catch (e) {
    return e.message;
  }
  const out: string[] = [];
  if (
    response.headers.get("content-type") !==
    privacypass.issuance.MediaType.PRIVATE_TOKEN_ISSUER_DIRECTORY
  ) {
    out.push(
      `Response content type ${response.headers.get(
        "content-type",
      )} does not match protocol ${privacypass.issuance.MediaType.PRIVATE_TOKEN_ISSUER_DIRECTORY}`,
    );
  }
  const issuers = await response.json();
  out.push(JSON.stringify(issuers, null, 2));
  return new TransformResult(
    out.join("\n"),
    ...issuers["token-keys"].flatMap((key) => [
      key["token-key"],
      new URL(url).host,
    ]),
  );
};

const createChallenge = async (
  ...issuersInfo: string[]
): Promise<TransformResult> => {
  let issuers: { name: string; publicKey: CryptoKey }[] = [];
  for (let i = 0; i < issuersInfo.length; i += 2) {
    const publicKey = issuersInfo[i];
    const name = issuersInfo[i + 1];
    if (publicKey === "") {
      continue;
    }
    issuers.push({ name, publicKey: await parsePublicKey(publicKey) });
  }

  let out: string[] = [];
  for (const issuer of issuers) {
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const originInfo = [new URL(window.origin).host];
    const tokChl = await privacypass.pubVerfiToken.createPrivateToken(
      issuer,
      redemptionContext,
      originInfo,
    );
    out.push(await tokChl.toString());
  }
  const challenge = out.join(", ");
  return new TransformResult(challenge, challenge);
};

const challengeParse = async (challenge: string): Promise<TransformResult> => {
  const tokens = await privacypass.httpAuthScheme.PrivateToken.parseMultiple(challenge);
  const infos = tokens.map((token) => ({
    challenge: {
      tokenType: token.challenge.tokenType,
      name: token.challenge.issuerName,
      origin: token.challenge.originInfo,
    },
    tokenKey: b64ToB64URL(u8ToB64(token.tokenKey)),
    maxAge: token.maxAge,
  }));
  return new TransformResult(JSON.stringify(infos, null, 2));
};

const challengeTrigger = async (
  challenge: string,
): Promise<TransformResult> => {
  try {
    const _response = await fetch(ECHO_URL, {
      method: "POST",
      headers: { "Content-Type": "text/plain", "WWW-Authenticate": challenge },
    });
    return new TransformResult("Challenge triggered");
  } catch (e) {
    return new TransformResult(e.message);
  }
};

const tokenParse = async (token: string) => {
  return notImplemented();
};

const challengeDebug = async (challenge: string) => {
  return privacypass.header_to_token(challenge);
};

const notImplemented = async () => "not implemented";

const onload = () => {
  Object.assign(window, {
    isLocalServerAvailable,
    checkExtension,
    validatePublicKey,
    fetchIssuers,
    createChallenge,
    challengeParse,
    challengeTrigger,
    tokenParse,
    challengeDebug,
    notImplemented,
  });
};

window.addEventListener("load", onload);