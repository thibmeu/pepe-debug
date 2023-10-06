import {
  MediaType,
  PrivateToken,
  TOKEN_TYPES,
  Token,
  TokenChallenge,
  header_to_token,
  util,
} from "@cloudflare/privacypass-ts";
import * as asn1 from "asn1js";

const u8ToB64 = (u: Uint8Array): string => btoa(String.fromCharCode(...u));

const b64Tou8 = (b: string): Uint8Array =>
  Uint8Array.from(atob(b), (c) => c.charCodeAt(0));

const b64ToB64URL = (s: string): string =>
  s.replace(/\+/g, "-").replace(/\//g, "_");

const b64URLtoB64 = (s: string): string =>
  s.replace(/-/g, "+").replace(/_/g, "/");

const LOCAL_URL = window.origin;
const ECHO_URL = `${LOCAL_URL}/echo-authentication`;
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
  const spkiEncoded = util.convertRSASSAPSSToEnc(pkEnc);
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
    const debugASN1 = (
      asn1.fromBER(b64Tou8(b64URLtoB64(pk))).result.valueBlock as any
    ).value.toString();
    return new TransformResult(debugASN1);
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
    MediaType.PRIVATE_TOKEN_ISSUER_DIRECTORY
  ) {
    out.push(
      `Response content type ${response.headers.get(
        "content-type",
      )} does not match protocol ${MediaType.PRIVATE_TOKEN_ISSUER_DIRECTORY}`,
    );
  }
  const issuers = await response.json();
  issuers["token-keys"] = issuers["token-keys"].map((key) =>
    Object.assign({}, key, {
      // the convertion is here to ensure there are no formatting issue
      // keys need to be encoded as RSAPSS
      "token-key": b64ToB64URL(
        u8ToB64(
          util.convertEncToRSASSAPSS(b64Tou8(b64URLtoB64(key["token-key"]))),
        ),
      ),
    }),
  );
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
  let issuers: { name: string; publicKey: Uint8Array }[] = [];
  for (let i = 0; i < issuersInfo.length; i += 2) {
    const publicKey = issuersInfo[i];
    const name = issuersInfo[i + 1];
    if (publicKey === "") {
      continue;
    }
    issuers.push({ name, publicKey: b64Tou8(b64URLtoB64(publicKey)) });
  }

  let out: string[] = [];
  for (const issuer of issuers) {
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const originInfo = [new URL(window.origin).host];
    const tokChl = new TokenChallenge(
      TOKEN_TYPES.BLIND_RSA.value,
      issuer.name,
      redemptionContext,
      originInfo,
    );
    const privateToken = new PrivateToken(tokChl, issuer.publicKey);
    out.push(privateToken.toString(true));
  }
  const challenge = out.join(", ");
  return new TransformResult(challenge, challenge);
};

const challengeParse = async (challenge: string): Promise<TransformResult> => {
  const tokens = PrivateToken.parse(challenge);
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
    const API_REPLAY_DELAY_IN_MS = 100;
    const API_REPLAY_HEADER = "private-token-client-replay";
    const API_REPLAY_URL =
      "https://no-reply.private-token.research.cloudflare.com";

    let response = await fetch(ECHO_URL, {
      headers: { "WWW-Authenticate": challenge },
    });
    // Client replay API when not supported by the platform
    const requestID = response.headers.get(API_REPLAY_HEADER);
    if (requestID) {
      const wait = () =>
        fetch(`${API_REPLAY_URL}?requestID=${requestID}`).then(
          async (response) => {
            const state = await response.text();
            return state === "pending";
          },
        );
      while (await wait()) {
        await new Promise((resolve) =>
          setTimeout(resolve, API_REPLAY_DELAY_IN_MS),
        );
      }
      response = await fetch(ECHO_URL);
    }
    const token = await response.text();
    return new TransformResult(token, token);
  } catch (e) {
    return new TransformResult(e.message);
  }
};

const tokenParse = async (token: string) => {
  const t = Token.parse(TOKEN_TYPES.BLIND_RSA, token)[0];
  return new TransformResult(
    JSON.stringify(
      {
        "token-type": t.payload.tokenType,
        "token-key-id": b64ToB64URL(u8ToB64(t.payload.tokenKeyId)),
        nonce: b64ToB64URL(u8ToB64(t.payload.nonce)),
        challengeDigest: b64ToB64URL(u8ToB64(t.payload.challengeDigest)),
        authenticator: b64ToB64URL(u8ToB64(t.authenticator)),
      },
      null,
      2,
    ),
  );
};

const challengeDebug = async (challenge: string) => {
  return header_to_token(challenge);
};

const notImplemented = async () => "not implemented";

const onload = () => {
  Object.assign(window, {
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
