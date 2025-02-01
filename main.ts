import { AutoRouter, cors, error } from "itty-router";
import { verifyJwt } from "@atproto/xrpc-server";
import { IdResolver } from "@atproto/identity";
import encodeBase32 from "base32-encode";
import {
  encodeRawMessage,
  parsePeerMessage,
  RouterMessageHeader,
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
const peers: { [did: string]: Peer } = {};

/** Handles the connection to a peer. */
class Peer {
  socket: WebSocket;
  did: string;
  /** The list of DIDs that the user wants to receive "join" and "leave" messages for. */
  listeningTo: string[] = [];

  constructor(did: string, socket: WebSocket) {
    this.did = did;
    this.socket = socket;
    this.socket.binaryType = "arraybuffer";

    socket.addEventListener("message", (e) => {
      if (e.data instanceof ArrayBuffer) {
        this.handleMessage(e.data);
      } else if (typeof e.data == "string") {
        this.handleMessage(new TextEncoder().encode(e.data));
      }
    });
  }

  handleMessage(buffer: ArrayBuffer) {
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
      this.sendJoinLeave(did, peers[did] ? "join" : "leave");
    }

    // Sending another peer a message
    else if (kind == "send") {
      const [did] = params;
      const peer = peers[did];
      // Forward data to the other peer
      if (peer) peer.sendData(this.did, data);
    }
  }

  sendJoinLeave(did: string, status: "join" | "leave") {
    encodeRawMessage<RouterMessageHeader>({
      // Send join or leave message based on whether other peer is connected
      header: [status, did],
      body: new Uint8Array(),
    });
  }

  /** Send a message to this peer. */
  sendData(from: string, data: Uint8Array) {
    this.socket.send(
      encodeRawMessage<RouterMessageHeader>({
        header: ["send", from],
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

  // Upgrade to websocket connection
  const { socket, response } = Deno.upgradeWebSocket(req);

  socket.addEventListener("open", () => {
    // Add the newly connected peer to our peers list
    peers[did] = new Peer(did, socket);

    // Notify any other peers that are listening for this peer's status.
    for (const peer of Object.values(peers)) {
      if (peer.listeningTo.includes(did)) {
        peer.sendJoinLeave(did, "join");
      }
    }
  });

  socket.addEventListener("close", () => {
    // Remove the peer from our connected peers list
    delete peers[did];

    // Notify any other peers that are listening for this peer's status.
    for (const peer of Object.values(peers)) {
      if (peer.listeningTo.includes(did)) {
        peer.sendJoinLeave(did, "leave");
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
router.get("/xrpc/town.muni.roomy.v0.router.token", async ({ did }: Ctx) => {
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
});

Deno.serve(router.fetch);
