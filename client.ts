import {
  encodeRawMessage,
  parseRouterMessage,
  type PeerMessageHeader,
} from "./encoding.ts";

type RouterClientCallbacks = {
  open?: () => void;
  close?: () => void;
  join?: (did: string, connId: string) => void;
  leave?: (did: string, connId?: string) => void;
  receive?: (did: string, connId: string, data: Uint8Array) => void;
  error?: (e: Event) => void;
};

export class RouterClient {
  socket: WebSocket;
  callbacks: RouterClientCallbacks;
  open: Promise<void>;
  listeningTo: string[] = [];
  knownConnections: { [did: string]: string[] } = {};

  constructor(
    token: string,
    url: string,
    callbacks: RouterClientCallbacks = {}
  ) {
    this.socket = new WebSocket(url, ["authorization", token]);
    this.socket.binaryType = "arraybuffer";
    this.callbacks = callbacks;

    this.socket.addEventListener("message", (e) => {
      if (e.data instanceof ArrayBuffer) {
        this.#handleMessage(e.data);
      } else if (typeof e.data == "string") {
        this.#handleMessage(new TextEncoder().encode(e.data));
      }
    });
    this.socket.addEventListener("error", (e) => {
      if (this.callbacks.error) this.callbacks.error(e);
    });
    this.socket.addEventListener("close", () => {
      if (this.callbacks.close) this.callbacks.close();
    });

    this.open = new Promise((resolve) => {
      this.socket.addEventListener("open", () => {
        if (this.callbacks.open) this.callbacks.open();
        resolve();
      });
    });
  }

  listen(...dids: string[]) {
    this.listeningTo = [...new Set(dids)];
    const oldConns = { ...this.knownConnections };
    this.knownConnections = {};
    this.listeningTo.forEach((did) => {
      this.knownConnections[did] = oldConns[did] || [];
    });

    this.socket.send(
      encodeRawMessage<PeerMessageHeader>({
        header: ["listen", ...this.listeningTo],
        body: new Uint8Array(),
      })
    );
  }

  ask(did: string) {
    this.socket.send(
      encodeRawMessage<PeerMessageHeader>({
        header: ["ask", did],
        body: new Uint8Array(),
      })
    );
  }

  send(did: string, connId: string, data: Uint8Array) {
    this.socket.send(
      encodeRawMessage<PeerMessageHeader>({
        header: ["send", did, connId],
        body: data,
      })
    );
  }

  #handleMessage(buffer: ArrayBuffer) {
    const msg = parseRouterMessage(buffer);
    if (msg instanceof Error) {
      console.warn(`Error parsing router message.`);
      return;
    }
    const [[kind, did, connId], data] = msg;

    if (kind == "join" && this.callbacks.join) {
      const conns = this.knownConnections[did] || [];
      conns.push(connId!);
      this.knownConnections[did] = conns;

      this.callbacks.join(did, connId!);
    } else if (kind == "leave" && this.callbacks.leave) {
      this.knownConnections[did] =
        this.knownConnections[did]?.filter((x) => x !== connId) || [];
      this.callbacks.leave(did, connId || undefined);
    } else if (kind == "send" && this.callbacks.receive) {
      this.callbacks.receive(did, connId!, data);
    }
  }
}
