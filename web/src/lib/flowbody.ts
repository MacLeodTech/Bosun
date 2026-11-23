// Flow bodies are fetched a page at a time from /flows/{id}/{part}/body (raw bytes, with Range), so a large
// response never has to fit in memory or in one JSON document.

import { b64ToBytes } from './bytes';
import type { FlowMeta, MessagePart } from './types';

/** How much of a body is fetched at once. */
export const PAGE = 256 * 1024;

export type PartName = 'request' | 'response' | 'original-request' | 'original-response';

/** One message, as far as it has been loaded. */
export interface Loaded {
  head: Uint8Array;
  /** Body bytes loaded so far (as stored, not decoded). */
  body: Uint8Array;
  /** Size of the whole stored body. */
  bodyLen: number;
  /** The decoded body so far, when the response has a content-encoding we undo. */
  decoded: Uint8Array | null;
  /** The decoded body goes on past what is loaded. */
  decodedMore: boolean;
  encoding: string | null;
  /** Why there is no decoded view, if there is none. */
  note: string;
}

export function bodyUrl(id: number, part: PartName, decoded = false): string {
  return `/api/v1/flows/${id}/${part}/body${decoded ? '?decoded=1' : ''}`;
}

export class BodyError extends Error {
  constructor(public status: number) {
    super(`HTTP ${status}`);
  }
}

/** `len` bytes from `start`. `total` is the whole length when the server says (not for a decoded body). */
export async function fetchRange(
  id: number, part: PartName, start: number, len: number, decoded = false,
): Promise<{ bytes: Uint8Array; total: number | null; end: boolean }> {
  const r = await fetch(bodyUrl(id, part, decoded), {
    headers: { range: `bytes=${start}-${start + len - 1}` },
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
  });
  if (r.status === 416) return { bytes: new Uint8Array(), total: null, end: true };
  if (!r.ok) throw new BodyError(r.status);
  const bytes = new Uint8Array(await r.arrayBuffer());
  const cr = r.headers.get('content-range');
  const m = cr?.match(/^bytes (\d+)-(\d+)\/(\d+|\*)$/);
  const total = m && m[3] !== '*' ? Number(m[3]) : null;
  // A 200 means the server sent everything; a short page means the end.
  return { bytes, total, end: r.status === 200 || bytes.length < len || (total !== null && start + bytes.length >= total) };
}

export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Load the head and the first page of a message (and of its decoded body, for a response with an encoding). */
export async function loadPart(meta: FlowMeta, part: PartName, info: MessagePart): Promise<Loaded> {
  const id = meta.id;
  const first = info.body_len > 0 ? await fetchRange(id, part, 0, PAGE) : { bytes: new Uint8Array() };
  const out: Loaded = {
    head: b64ToBytes(info.head),
    body: first.bytes,
    bodyLen: info.body_len,
    decoded: null,
    decodedMore: false,
    encoding: part === 'response' ? meta.response_encoding : null,
    note: '',
  };
  if (out.encoding && info.body_len > 0) {
    try {
      const d = await fetchRange(id, part, 0, PAGE, true);
      out.decoded = d.bytes;
      out.decodedMore = !d.end;
    } catch (e) {
      out.note = e instanceof BodyError && e.status === 415 ? `unsupported content-encoding ${out.encoding}` : 'could not decode the body';
    }
  }
  return out;
}

/** The next page of the stored body, or of the decoded one. */
export async function loadMore(meta: FlowMeta, part: PartName, cur: Loaded, decoded: boolean): Promise<Loaded> {
  if (decoded && cur.decoded) {
    const d = await fetchRange(meta.id, part, cur.decoded.length, PAGE, true);
    return { ...cur, decoded: concat(cur.decoded, d.bytes), decodedMore: !d.end };
  }
  const n = await fetchRange(meta.id, part, cur.body.length, PAGE);
  return { ...cur, body: concat(cur.body, n.bytes) };
}
