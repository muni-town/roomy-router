import { AutoRouter, cors, error } from "itty-router";
import { verifyJwt } from "@atproto/xrpc-server";
import { IdResolver } from "@atproto/identity";
import encodeBase32 from "base32-encode";
import {
  encodeRawMessage,
  parsePeerMessage,
  type RouterMessageHeader,
} from "./encoding.ts";

// Open the key-value database
const kv = await Deno.openKv();

// TODO: add a DID cache using Deno KV
const idResolver = new IdResolver();
async function getSigningKey(
  did: string,
  forceRefresh: boolean
): Promise<string> {
  const atprotoData = await idResolver.did.resolveAtprotoData(
    did,
    forceRefresh
  );
  return atprotoData.signingKey;
}

// Create HTTP router
const { preflight, corsify } = cors();
const router = AutoRouter({
  before: [preflight],
  finally: [corsify],
});

// Parse configuration environment variables.
const serviceDid = Deno.env.get("DID");
const unsafeDevToken = Deno.env.get("UNSAFE_DEV_TOKEN");

if (!serviceDid)
  throw new Error(
    "Must set DID environment variable to the DID of this deployed service."
  );

// Return the service DID
router.get("/.well-known/did.json", ({ url }) => ({
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: serviceDid,
  service: [
    {
      id: "#roomy_router",
      type: "RoomyRouter",
      serviceEndpoint: (() => {
        const u = new URL(url);
        u.pathname = "/";
        return u.href;
      })(),
    },
  ],
}));

/** All of the open peer connections. */
const peerConns: { [did: string]: { [connId: string]: Peer } } = {};

/** Handles the connection to a peer. */
class Peer {
  socket: WebSocket;
  did: string;
  connId: string;
  /** The list of DIDs that the user wants to receive "join" and "leave" messages for. */
  listeningTo: string[] = [];

  constructor(did: string, connId: string, socket: WebSocket) {
    this.did = did;
    this.connId = connId;
    this.socket = socket;
    this.socket.binaryType = "arraybuffer";

    socket.addEventListener("message", (e) => {
      if (e.data instanceof ArrayBuffer) {
        this.#handleMessage(e.data);
      } else if (typeof e.data == "string") {
        this.#handleMessage(new TextEncoder().encode(e.data));
      }
    });
  }

  #handleMessage(buffer: ArrayBuffer) {
    const msg = parsePeerMessage(buffer);
    if (msg instanceof Error) {
      console.warn(`Error parsing message for ${this.did}`);
      return;
    }
    const [[kind, ...params], data] = msg;

    // Setting the peers this peer should receive status updates for
    if (kind == "listen") {
      this.listeningTo = params;
    }

    // Asking for other peer's status
    else if (kind == "ask") {
      const [did] = params;
      const connections = peerConns[did];
      if (Object.keys(connections || {}).length == 0) {
        this.sendJoinLeave("leave", did);
      } else {
        for (const connId of Object.keys(connections)) {
          this.sendJoinLeave("join", did, connId);
        }
      }
    }

    // Sending another peer a message
    else if (kind == "send") {
      const [did, connId] = params;
      // Forward data to the other peer's connection
      peerConns[did]?.[connId]?.sendData(this.did, connId, data);
    }
  }

  sendJoinLeave(status: "join" | "leave", did: string, connId?: string) {
    this.socket.send(
      encodeRawMessage<RouterMessageHeader>({
        // Send join or leave message based on whether other peer is connected
        header: [status, did, connId],
        body: new Uint8Array(),
      })
    );
  }

  /** Send a message to this peer. */
  sendData(fromDid: string, connId: string, data: Uint8Array) {
    this.socket.send(
      encodeRawMessage<RouterMessageHeader>({
        header: ["send", fromDid, connId],
        body: data,
      })
    );
  }
}

// Open a websocket connection to the routing service.
router.get("/connect/as/:did", async (req) => {
  const { headers, params } = req;

  // Get that the user is trying to connect as from the URL.
  const did = params.did!;

  // Make sure this is a websocket request
  if (headers.get("upgrade") != "websocket") {
    return error(400, "Must set `upgrade` header to `websocket`.");
  }

  // Get the authorization token from the header
  const token = headers
    .get("Sec-WebSocket-Protocol")
    ?.split("authorization,")[1]
    ?.trim();
  if (!token) return error(403, "Missing authorization bearer token");

  // Load the token and make sure the DID matches to make sure it's valid.
  const tokenDid = (await kv.get<string>(["tokens", token])).value;

  if (did !== tokenDid && !(unsafeDevToken && token === unsafeDevToken))
    return error(403, "Token invalid or expired");

  // Generate a connection ID
  const connId = encodeBase32(
    crypto.getRandomValues(new Uint8Array(8)),
    "Crockford"
  );

  // Upgrade to websocket connection
  const { socket, response } = Deno.upgradeWebSocket(req);

  socket.addEventListener("open", () => {
    // Add the newly connected peer to our peers list
    const connections = peerConns[did];
    if (!connections) peerConns[did] = {};
    peerConns[did][connId] = new Peer(did, connId, socket);
    console.info(`New peer connected: ${did}(${connId})`);

    // Notify any other peers that are listening for this peer's status.
    for (const conns of Object.values(peerConns)) {
      for (const conn of Object.values(conns)) {
        if (conn.listeningTo.includes(did)) {
          conn.sendJoinLeave("join", did, connId);
        }
      }
    }
  });

  socket.addEventListener("close", () => {
    // Remove the peer from our connected peers list
    const conns = peerConns[did] || {};
    delete conns[connId];
    console.info(`Peer disconnected: ${did}(${connId})`);

    // Notify any other peers that are listening for this peer's status.
    for (const conns of Object.values(peerConns)) {
      for (const conn of Object.values(conns)) {
        if (conn.listeningTo.includes(did)) {
          conn.sendJoinLeave("leave", did, connId);
        }
      }
    }
  });

  return response;
});

//
// AUTH WALL
//
// ALL REQUESTS PAST THIS POINT REQUIRE AUTH
//

type JwtPayload = Awaited<ReturnType<typeof verifyJwt>>;
type AuthCtx = {
  jwtPayload: JwtPayload;
  did: string;
};
type Ctx = Request & AuthCtx;

router.all("*", async (ctx) => {
  const url = new URL(ctx.url);
  if (!url.pathname.startsWith("/xrpc/")) return error(404);
  const lxm = url.pathname.split("/xrpc/")[1];

  const authorization = ctx.headers.get("authorization");
  if (!authorization) return error(403, "Authorization token required.");
  if (!authorization.startsWith("Bearer "))
    return error(403, "Bearer token required");
  const jwt = authorization.split("Bearer ")[1];
  let jwtPayload: JwtPayload;
  try {
    jwtPayload = await verifyJwt(jwt, serviceDid, lxm, getSigningKey);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error("Error validating JWT:", e);
    return error(403, "Could not validate authorization JWT.");
  }

  ctx.jwtPayload = jwtPayload;
  ctx.did = jwtPayload.iss;

  return undefined;
});

// Get an access token that can be used to open up a WebSocket connection to the router.
router.get("/xrpc/chat.roomy.v0.router.token", async ({ did }: Ctx) => {
  // Generate a new token
  const token = encodeBase32(
    crypto.getRandomValues(new Uint8Array(32)),
    "Crockford"
  );
  // Add the token to the key-value store and give it a lifetime of 30 seconds. Login attempts after
  // that time will fail.
  await kv.set(["tokens", token], did, {
    expireIn: 30000,
  });

  return {
    token,
  };
});

Deno.serve(router.fetch);
