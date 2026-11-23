// JSON shapes of the Bosun API (see crates/bosun-api).
import type { components } from './api-types';

export type Role = 'viewer' | 'tester' | 'admin';
export interface User { id: number; username: string; role: Role; created_ms: number }
export interface Me { user: User; csrf: string | null }

export interface FlowSummary {
  id: number; source: string; started_ms: number; duration_ms?: number | null;
  scheme: 'http' | 'https'; host: string; port: number; method: string; path: string; http_version: string;
  status?: number | null; request_len: number; response_len?: number | null; mime?: string | null;
  in_scope: boolean; edited: boolean; error?: string | null; tags: string[]; note?: string | null;
}
/** One stored message: its header block (base64) and sizes. The body is fetched separately. */
export interface MessagePart { head: string; total_len: number; body_len: number }
/** A flow without bodies (`GET /flows/{id}`). */
export type FlowMeta = FlowSummary & {
  request: MessagePart; original_request: MessagePart | null;
  response: MessagePart | null; original_response: MessagePart | null;
  response_truncated: boolean;
  /** The response's Content-Encoding, if it has one. */
  response_encoding: string | null;
};
export interface WsMessage {
  id: number; flow_id: number; time_ms: number; direction: 'client_to_server' | 'server_to_client';
  opcode: number; payload: string; truncated: boolean;
}
export interface SiteMapEntry {
  scheme: string; host: string; port: number; path: string; methods: string[];
  last_status: number | null; count: number; in_scope: boolean;
}
export interface ScopeRule { scheme?: 'http' | 'https' | null; host: string; port?: number | null; path?: string | null; allow_private?: boolean }
export interface ScopeSpec { include: ScopeRule[]; exclude: ScopeRule[] }
export type RuleTarget = 'request_first_line' | 'request_header' | 'request_body'
  | 'response_first_line' | 'response_header' | 'response_body';
export interface MatchRule { enabled: boolean; target: RuleTarget; match: string; replace: string; regex: boolean; comment?: string }
export interface InterceptSettings { requests: boolean; responses: boolean; in_scope_only: boolean; timeout_secs?: number | null }
export interface InterceptSummary {
  id: number; flow_id: number; phase: 'request' | 'response'; method: string; url: string;
  status?: number | null; queued_ms: number;
}
export interface InterceptItem extends InterceptSummary { raw: string }
export interface ApiToken { id: number; name: string; user_id: number; created_ms: number; last_used_ms: number | null; expires_ms: number | null; scope: 'read' | 'full' }
export interface SessionInfo { id: string; user_id: number; created_ms: number; expires_ms: number }
export interface AuditEntry { id: number; time_ms: number; username: string | null; action: string; detail: string; remote: string | null }

/** What the server sends, from the generated description; plus the two messages of the resume protocol, which
 * are not events of the proxy (see `crates/bosun-api/src/events.rs`). */
export type ProxyEvent =
  | components['schemas']['ProxyEvent']
  | { type: 'hello'; epoch: string; seq: number }
  /** Events were missed that cannot be replayed (or another project is open): fetch the data again. */
  | { type: 'reload' };

export interface CurrentProject { name?: string | null; temporary: boolean; external: boolean }
export interface ProjectInfo { name: string; size_bytes: number; modified_ms: number; current: boolean }
export interface ProjectList { current: CurrentProject; projects: ProjectInfo[]; recent: string[] }

// The shapes above are written by hand for the UI; these checks fail the build if the generated description of
// the API (api-types.ts, from docs/openapi.json) stops agreeing with them.
type Schemas = components['schemas'];
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
const agree = <_T extends true>() => {};
agree<Same<Role, Schemas['Role']>>();
agree<Same<Me['user'], Schemas['User']>>();
agree<Same<ApiToken['scope'], Schemas['TokenScope']>>();
agree<Same<keyof FlowSummary, keyof Schemas['FlowSummary']>>();
agree<Same<keyof InterceptSettings, keyof Schemas['InterceptSettings']>>();
agree<Same<keyof AuditEntry, keyof Schemas['AuditEntry']>>();
agree<Same<CurrentProject, Schemas['CurrentProject']>>();
agree<Same<keyof ProjectInfo, keyof Schemas['ProjectInfo']>>();
agree<Same<keyof ProjectList, keyof Schemas['ProjectList']>>();
