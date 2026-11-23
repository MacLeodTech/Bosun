// JSON shapes of the Bosun API (see crates/bosun-api).

export type Role = 'viewer' | 'tester' | 'admin';
export interface User { id: number; username: string; role: Role; created_ms: number }
export interface Me { user: User; csrf: string | null }

export interface FlowSummary {
  id: number; source: string; started_ms: number; duration_ms: number | null;
  scheme: 'http' | 'https'; host: string; port: number; method: string; path: string; http_version: string;
  status: number | null; request_len: number; response_len: number; mime: string | null;
  in_scope: boolean; edited: boolean; error: string | null; tags: string[]; note: string | null;
}
export interface FlowDetail {
  summary: FlowSummary;
  request: string; original_request: string | null;
  response: string | null; original_response: string | null;
  response_truncated: boolean;
  response_body_decoded: string | null; decode_note: string | null;
}
export interface WsMessage {
  id: number; flow_id: number; time_ms: number; direction: 'client_to_server' | 'server_to_client';
  opcode: number; payload: string; truncated: boolean;
}
export interface SiteMapEntry {
  scheme: string; host: string; port: number; path: string; methods: string[];
  last_status: number | null; count: number; in_scope: boolean;
}
export interface ScopeRule { scheme?: 'http' | 'https' | null; host: string; port?: number | null; path?: string | null }
export interface ScopeSpec { include: ScopeRule[]; exclude: ScopeRule[] }
export type RuleTarget = 'request_first_line' | 'request_header' | 'request_body'
  | 'response_first_line' | 'response_header' | 'response_body';
export interface MatchRule { enabled: boolean; target: RuleTarget; match: string; replace: string; regex: boolean; comment?: string }
export interface InterceptSettings { requests: boolean; responses: boolean; in_scope_only: boolean; timeout_secs?: number | null }
export interface InterceptSummary {
  id: number; flow_id: number; phase: 'request' | 'response'; method: string; url: string;
  status: number | null; queued_ms: number;
}
export interface InterceptItem extends InterceptSummary { raw: string }
export interface ApiToken { id: number; name: string; user_id: number; created_ms: number; last_used_ms: number | null; expires_ms: number | null; scope: 'read' | 'full' }
export interface SessionInfo { id: string; user_id: number; created_ms: number; expires_ms: number }
export interface AuditEntry { id: number; time_ms: number; username: string | null; action: string; detail: string; remote: string | null }

export type ProxyEvent =
  | { type: 'flow'; flow: FlowSummary }
  | { type: 'ws_message'; flow_id: number; direction: string; opcode: number; len: number }
  | { type: 'intercept_queued'; item: InterceptSummary }
  | { type: 'intercept_resolved'; id: number }
  | { type: 'intercept_state'; requests: number; responses: number }
  | { type: 'intercept_refused'; reason: string }
  | { type: 'recorder_failed'; lost: number; error: string }
  | { type: 'lagged'; missed: number };
