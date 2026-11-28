// Which Decoder steps turn a body into readable text, and back, by its Content-Type.

export type ProtoSteps = { decode: string[]; encode: string[] };

/** gRPC and gRPC-Web bodies; null for anything else. */
export function grpcSteps(contentType: string): ProtoSteps | null {
  const ct = contentType.toLowerCase();
  if (/^application\/grpc-web-text/.test(ct)) return { decode: ['base64_decode', 'grpc_decode'], encode: ['grpc_encode', 'base64_encode'] };
  if (/^application\/grpc/.test(ct)) return { decode: ['grpc_decode'], encode: ['grpc_encode'] };
  return null;
}

/** The path of a request's first line (`POST /pkg.Service/Method HTTP/1.1`): a gRPC call's name. */
export function requestPath(head: string): string | undefined {
  const m = /^[A-Z]+ (\S+)/.exec(head);
  return m ? m[1]!.split(/[?#]/)[0] : undefined;
}
