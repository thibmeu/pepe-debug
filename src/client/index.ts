import {
  AuthorizationHeader,
  Extension,
  Extensions,
  IssuerConfig,
  MediaType,
  TOKEN_TYPES,
  Token,
  TokenChallenge,
  WWWAuthenticateHeader,
  header_to_token,
  privateVerif,
  publicVerif,
  util,
} from "@cloudflare/privacypass-ts";
import * as asn1 from "asn1js";

const hex_decode = (s: string) => {
  if (s.startsWith("0x")) {
    s = s.slice(2);
  }
  return Uint8Array.from(s.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
};

const hex_encode = (u: Uint8Array) =>
  Array.from(u)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

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

const SUPPORTED_TOKEN_TYPES = Object.values(TOKEN_TYPES).map(
  (tokenType) => tokenType.value,
);

class TransformResult {
  private _string: string;
  private _fill: Record<string, string | string[]>;

  constructor(s: string, fill: Record<string, string | string[]> = {}) {
    this._string = s;
    this._fill = fill;
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

  return fetch(request, params);
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

const validatePublicKey = async ({
  type,
  key: pk,
}: {
  type: string;
  key: string;
}): Promise<TransformResult> => {
  const tokenType = Number.parseInt(type);
  if (!SUPPORTED_TOKEN_TYPES.includes(tokenType)) {
    return new TransformResult(
      `Token type 0x${tokenType.toString(16)} is not supported.`,
    );
  }

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

const fetchIssuers = async ({
  "issuer-directory-uri": url,
}: {
  "issuer-directory-uri": string;
}): Promise<TransformResult> => {
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
  const issuers: IssuerConfig = await response.json();
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
  return new TransformResult(out.join("\n"), {
    type: issuers["token-keys"].map((key) => key["token-type"].toString()),
    key: issuers["token-keys"].map((key) => key["token-key"]),
    "issuer-name": issuers["token-keys"].map(() => new URL(url).host),
    "issuer-request-uri": issuers["token-keys"].map(
      () => `${new URL(url).origin}${issuers["issuer-request-uri"]}`,
    ), // note this won't work if issuer-request-uri is absolute
  });
};

const createChallenge = async ({
  type: types,
  key: keys,
  "issuer-name": names,
}: {
  type: string[];
  key: string[];
  "issuer-name": string[];
}): Promise<TransformResult> => {
  let issuers: { tokenType: number; name: string; publicKey: Uint8Array }[] =
    [];
  for (let i = 0; i < keys.length; i += 1) {
    const tokenType = Number.parseInt(types[i]);
    const publicKey = keys[i];
    const name = names[i];
    if (publicKey === "") {
      continue;
    }
    issuers.push({
      tokenType,
      name,
      publicKey: b64Tou8(b64URLtoB64(publicKey)),
    });
  }

  let out: string[] = [];
  for (const issuer of issuers) {
    const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
    const originInfo = [new URL(window.origin).host];
    const tokChl = new TokenChallenge(
      issuer.tokenType,
      issuer.name,
      redemptionContext,
      originInfo,
    );
    const privateToken = new WWWAuthenticateHeader(tokChl, issuer.publicKey);
    out.push(privateToken.toString(true));
  }
  const challenge = out.join(", ");
  return new TransformResult(challenge, { challenge });
};

const challengeParse = async ({
  challenge,
}: {
  challenge: string;
}): Promise<TransformResult> => {
  const tokens = WWWAuthenticateHeader.parse(challenge);
  const infos = await Promise.all(
    tokens.map(async (token) => ({
      challenge: {
        tokenType: token.challenge.tokenType,
        name: token.challenge.issuerName,
        origin: token.challenge.originInfo,
        redemptionContext: b64ToB64URL(
          u8ToB64(token.challenge.redemptionContext),
        ),
      },
      tokenKey: b64ToB64URL(u8ToB64(token.tokenKey)),
      tokenKeyId: b64ToB64URL(
        u8ToB64(
          new Uint8Array(await crypto.subtle.digest("SHA-256", token.tokenKey)),
        ),
      ),
      maxAge: token.maxAge,
    })),
  );
  return new TransformResult(JSON.stringify(infos, null, 2));
};

const challengeTrigger = async ({
  challenge,
}: {
  challenge: string;
}): Promise<TransformResult> => {
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
    if (!response.ok && response.headers.get("WWW-Authenticate")) {
      throw new Error(
        `Challenge has been triggered, but the platform failed to return an Authorization header. Status: ${response.status} ${response.statusText}`,
      );
    }
    const token = await response.text();
    return new TransformResult(token, { token });
  } catch (e) {
    return new TransformResult(e.message);
  }
};

const tokenRequest = async ({
  key: pk,
  "issuer-request-uri": url,
  challenge,
  extensions: extensionsRaw,
}: {
  key: string;
  "issuer-request-uri": string;
  challenge: string;
  extensions: string;
}) => {
  console.log("========", pk, url, challenge, extensionsRaw);
  const tokens = WWWAuthenticateHeader.parse(challenge);
  const extensions =
    extensionsRaw !== ""
      ? Extensions.deserialize(b64Tou8(b64URLtoB64(extensionsRaw)))
      : null;
  const publicKey = await parsePublicKey(pk); // always the public key of the first token
  for (const token of tokens) {
    const result: string[] = [];
    const getTokenType = (tokenType: number) =>
      Object.values(TOKEN_TYPES).find((x) => x.value === tokenType)!;
    const tokenType = getTokenType(token.challenge.tokenType);

    let client: {
      createTokenRequest: (
        ...params: Parameters<publicVerif.Client["createTokenRequest"]>
      ) => Promise<{ serialize: publicVerif.TokenRequest["serialize"] }>;
      finalize: publicVerif.Client["finalize"];
    };
    let origin: Pick<publicVerif.Origin, "verify">;
    if (tokenType.publicVerifiable) {
      if (tokenType.publicMetadata) {
        if (extensions === null) {
          return new TransformResult(
            `Extension must be defined for token type ${token.challenge.tokenType}`,
          );
        }
        const _client = new publicVerif.ClientWithMetadata(
          publicVerif.PartiallyBlindRSAMode.PSS,
          extensions,
        );
        client = {
          createTokenRequest(...params) {
            return _client.createTokenRequest.bind(_client)(...params);
          },
          finalize(...params) {
            return _client.finalize.bind(_client)(...params);
          },
        };
        origin = new publicVerif.OriginWithMetadata(
          publicVerif.PartiallyBlindRSAMode.PSS,
          extensions,
        );
      } else {
        const _client = new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
        client = {
          createTokenRequest: (...params) =>
            _client.createTokenRequest.bind(_client)(...params),
          finalize(...params) {
            return _client.finalize.bind(_client)(...params);
          },
        };
        origin = new publicVerif.Origin(publicVerif.BlindRSAMode.PSS);
      }
    } else {
      if (tokenType.privateMetadata) {
        return notImplemented();
      } else {
        return notImplemented();
      }
    }
    let validToken: Token;
    try {
      const request = await client.createTokenRequest(
        token.challenge,
        token.tokenKey,
      );
      console.log(request);

      // console.log("________", request.serialize());
      const response = await proxyFetch(url, {
        method: "POST",
        headers: {
          "Content-Type": MediaType.PRIVATE_TOKEN_REQUEST,
          Accept: MediaType.PRIVATE_TOKEN_RESPONSE,
        },
        body: request.serialize(),
      });

      const tokenResponse = publicVerif.TokenResponse.deserialize(
        new Uint8Array(await response.arrayBuffer()),
      );
      console.log('finalizeToken')
      validToken = await client.finalize(tokenResponse);
      console.log('====== validToken', validToken)
      result.push(
        `Draft 16 Valid: ${
          (await origin.verify(validToken, publicKey)) &&
          response.headers.get("Content-Type") ===
            MediaType.PRIVATE_TOKEN_RESPONSE
        }`,
      );
      result.push(new AuthorizationHeader(validToken).toString(true));
    } catch (e) {
      return new TransformResult(e.message);
    }

    // Test old protocol which has not been standardised
    try {
      const request = await client.createTokenRequest(
        token.challenge,
        token.tokenKey,
      );
      const oldProtocolResponse = await proxyFetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "message/token-request",
          Accept: "message/token-response",
        },
        body: request.serialize(),
      });

      const tokenResponse = publicVerif.TokenResponse.deserialize(
        new Uint8Array(await oldProtocolResponse.arrayBuffer()),
      );
      const validOldToken = await client.finalize(tokenResponse);
      result.push(
        `Draft 2 Valid: ${
          (await origin.verify(validOldToken, publicKey)) &&
          oldProtocolResponse.headers.get("Content-Type") ===
            "message/token-response"
        }`,
      );
    } catch (e) {
      console.log(e);
      // ignore if the old protocol is not supported
    }

    return new TransformResult(result.join("\n"), {
      token: new AuthorizationHeader(validToken).toString(true),
    });
  }
};

const tokenParse = async ({ token }: { token: string }) => {
  const header = AuthorizationHeader.parse(TOKEN_TYPES.BLIND_RSA, token)[0];
  let { token: t, extensions } = header;
  if (!t) {
    return new TransformResult("Cannot parse token.");
  }
  const encoded = extensions?.serialize();
  const e = encoded ? b64ToB64URL(u8ToB64(encoded)) : "";
  return new TransformResult(
    JSON.stringify(
      {
        "token-type": t.authInput.tokenType,
        "token-key-id": b64ToB64URL(u8ToB64(t.authInput.tokenKeyId)),
        nonce: b64ToB64URL(u8ToB64(t.authInput.nonce)),
        challengeDigest: b64ToB64URL(u8ToB64(t.authInput.challengeDigest)),
        authenticator: b64ToB64URL(u8ToB64(t.authenticator)),
      },
      null,
      2,
    ),
    {
      extensions: e,
    },
  );
};

const tokenVerify = async ({
  key: pk,
  token,
}: {
  key: string;
  token: string;
}) => {
  const publicKey = await parsePublicKey(pk);
  const responseToken = AuthorizationHeader.parse(
    TOKEN_TYPES.BLIND_RSA,
    token,
  )[0].token;

  const origin = new publicVerif.Origin(publicVerif.BlindRSAMode.PSS);

  if (await origin.verify(responseToken, publicKey)) {
    return new TransformResult("Token matches the public key.");
  }
  return new TransformResult("Token does not match the public key.");
};

const createExtensions = async ({
  "extension-type": types,
  "extension-info": infos,
}: {
  "extension-type": string[];
  "extension-info": string[];
}) => {
  const extensionsArray: Extension[] = [];
  for (let i = 0; i < types.length; i += 1) {
    const type = types[i];
    const info = infos[i];
    if (type === "" || info === "") {
      continue;
    }
    extensionsArray.push(
      new Extension(Number.parseInt(type), hex_decode(info)),
    );
  }
  const extensions = new Extensions(extensionsArray);
  const encoded = b64ToB64URL(u8ToB64(extensions.serialize()));
  return new TransformResult(encoded, { extensions: encoded });
};

const extensionsParse = async ({
  extensions: extensionsRaw,
}: {
  extensions: string;
}) => {
  const decoded = b64Tou8(b64URLtoB64(extensionsRaw));
  const extensions = Extensions.deserialize(decoded);
  return new TransformResult(
    JSON.stringify(
      extensions.extensions.map((v) => ({
        type: v.extensionType,
        info: hex_encode(v.extensionData),
      })),
      null,
      2,
    ),
    {
      "extensions-type": extensions.extensions.map((v) =>
        v.extensionType.toString(),
      ),
      "extensions-info": extensions.extensions.map((v) =>
        hex_encode(v.extensionData),
      ),
    },
  );
};

const challengeDebug = async ({ challenge }: { challenge: string }) => {
  return header_to_token(challenge);
};

const notImplemented = async () => "not implemented";

const onload = () => {
  Object.assign(window, {
    validatePublicKey,
    fetchIssuers,
    createChallenge,
    challengeParse,
    challengeTrigger,
    tokenRequest,
    tokenParse,
    tokenVerify,
    createExtensions,
    extensionsParse,
    challengeDebug,
    notImplemented,
  });
};

window.addEventListener("load", onload);
