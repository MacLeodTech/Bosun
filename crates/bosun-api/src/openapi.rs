//! The API's OpenAPI description, built from the types the handlers use.
//!
//! `docs/openapi.json` is generated from this (`cargo test -p bosun-api --test openapi` rewrites it with
//! `BLESS=1`), and CI fails if the two differ. The test also calls every documented route on the real router,
//! so a path that is documented but not served is caught. Handlers are not annotated one by one: the
//! operations live here, next to the response shapes that the handlers build with `json!`.

#![allow(dead_code)]

use serde::Serialize;
use utoipa::OpenApi;
use utoipa::ToSchema;

use bosun_model::{FlowSummary, WsMessage};
use bosun_proxy::intercept::{Decision, InterceptItem, InterceptSettings, InterceptSummary, ResponseFilter};
use bosun_proxy::{ProxyEvent, ProxyStats};
use bosun_store::{ApiToken, AuditEntry, FlowMeta, Role, SessionInfo, SiteMapEntry, TokenScope, User};

use crate::codec::{DecodeBody, DecodeReply, DiffBody, SmartBody};
use crate::handlers::{ChangeTags, FlowOverview, OrganizerAdd, OrganizerChange, QueryCheck, SavedFilter};
use crate::intruder::{AttackDetail, AttackInfo, AttackList, PlanReply, ResultsReply, StartBody, StopReply};
use crate::issues::{IssueChange, IssueList};
use crate::projects::{BackupInfo, CurrentProject, NewProject, ProjectInfo, ProjectList, RenameProject};
use crate::repeater::{RepeaterSettings, SendBody, SendReply, TabsDoc, WsBody, WsReply};
use crate::sequencer::{AnalyzeBody, CaptureBody, CaptureStarted, CaptureStatus};
use bosun_proxy::rules::RuleSpec as MatchRule;
use bosun_scope::ScopeSpec;

#[derive(ToSchema, Serialize)]
pub struct Error {
    pub error: String,
}
#[derive(ToSchema, Serialize)]
pub struct Status {
    pub name: String,
    pub version: String,
    pub setup_required: bool,
}
#[derive(ToSchema, Serialize)]
pub struct Me {
    pub user: User,
    /** Present for cookie sessions: send it as `x-csrf-token` on changes. */
    pub csrf: Option<String>,
}
#[derive(ToSchema, Serialize)]
pub struct SsoButton {
    pub name: String,
    pub login: String,
    pub edge: Option<String>,
}
#[derive(ToSchema, Serialize)]
pub struct SsoInfo {
    pub sso: Option<SsoButton>,
}
#[derive(ToSchema, Serialize)]
pub struct Deleted {
    pub deleted: u64,
}
#[derive(ToSchema, Serialize)]
pub struct AddedCount {
    pub added: u64,
}
#[derive(ToSchema, Serialize)]
pub struct ChangedCount {
    pub changed: u64,
}
#[derive(ToSchema, Serialize)]
pub struct Forwarded {
    pub forwarded: u64,
}
#[derive(ToSchema, Serialize)]
pub struct Revoked {
    pub revoked: u64,
}
#[derive(ToSchema, Serialize)]
pub struct Stopped {
    pub stopped: bool,
}
#[derive(ToSchema, Serialize)]
pub struct Launched {
    pub launched: String,
}
#[derive(ToSchema, Serialize)]
pub struct CaInfo {
    pub fingerprint_sha256: String,
    pub spki_sha256: String,
    pub pem: String,
    /// Expiry, seconds since the Unix epoch.
    pub not_after: i64,
    /// Whole days until expiry (negative once expired).
    pub days_left: i64,
    /// True when the CA expires within 30 days or already has.
    pub expiring: bool,
    /// Domains a name-constrained CA is limited to; empty when unconstrained.
    pub permitted_domains: Vec<String>,
}
#[derive(ToSchema, Serialize)]
pub struct NewTokenReply {
    pub token: String,
    pub info: ApiToken,
}
#[derive(ToSchema, Serialize)]
pub struct ProxyInfo {
    pub listen: String,
    pub http2: bool,
    pub invisible: bool,
    pub verify_upstream_tls: bool,
    pub upstream: Option<String>,
    pub tls_passthrough: Vec<String>,
    pub auth_required: bool,
    pub record_out_of_scope: bool,
    pub tools_stopped: bool,
    pub stats: ProxyStats,
}
#[derive(ToSchema, Serialize)]
pub struct SetupBody {
    pub code: String,
    pub username: String,
    pub password: String,
}
#[derive(ToSchema, Serialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}
#[derive(ToSchema, Serialize)]
pub struct TicketBody {
    /** The single-use ticket an embedded engine printed for its parent. */
    pub ticket: String,
}
#[derive(ToSchema, Serialize)]
pub struct PasswordBody {
    pub current: String,
    pub new: String,
    /** Also end the user's API tokens (default true). */
    pub revoke_tokens: Option<bool>,
}
#[derive(ToSchema, Serialize)]
pub struct SecondFactor {
    /** The kind of second factor to present: `totp`. */
    pub second_factor: String,
    /** Send this with the code to `POST /auth/login/totp`. Valid for five minutes, from the same address. */
    pub pending: String,
}
/// The answer to a password sign-in: a session, or a request for the second factor (no session yet).
#[derive(ToSchema, Serialize)]
#[serde(untagged)]
pub enum LoginReply {
    Signed(Me),
    SecondFactor(SecondFactor),
}
#[derive(ToSchema, Serialize)]
pub struct TotpLoginBody {
    pub pending: String,
    /** A 6-digit code, or an unused recovery code. */
    pub code: String,
}
#[derive(ToSchema, Serialize)]
pub struct TotpCodeBody {
    /** A 6-digit code (a recovery code also works where the operation allows it). */
    pub code: String,
}
#[derive(ToSchema, Serialize)]
pub struct TotpStatus {
    /** A confirmed second factor is on for this account. */
    pub enabled: bool,
    /** A secret was made but no code has confirmed it yet. */
    pub enrolling: bool,
    pub recovery_codes_left: i64,
    /** An admin requires every password account to have a second factor. */
    pub required: bool,
    /** This account must set up a second factor before it can do anything else. */
    pub setup_required: bool,
}
#[derive(ToSchema, Serialize)]
pub struct TotpEnrolment {
    /** The shared secret, base32. Shown once. */
    pub secret: String,
    /** The same secret as an `otpauth://` URI. */
    pub otpauth_uri: String,
}
#[derive(ToSchema, Serialize)]
pub struct RecoveryCodes {
    /** Shown once; each works once. */
    pub recovery_codes: Vec<String>,
}
#[derive(ToSchema, Serialize)]
pub struct TotpRequiredBody {
    pub required: bool,
}
#[derive(ToSchema, Serialize)]
pub struct DeleteFlows {
    pub ids: Vec<i64>,
}
#[derive(ToSchema, Serialize)]
pub struct Annotate {
    pub tags: Option<Vec<String>>,
    pub note: Option<String>,
}
#[derive(ToSchema, Serialize)]
pub struct StopBody {
    pub stopped: bool,
}
#[derive(ToSchema, Serialize)]
pub struct NewToken {
    pub name: String,
    pub expires_days: Option<u32>,
    pub scope: Option<TokenScope>,
}
#[derive(ToSchema, Serialize)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub role: Role,
}
#[derive(ToSchema, Serialize)]
pub struct RoleBody {
    pub role: Role,
}
/// Not JSON: raw bytes.
#[derive(ToSchema, Serialize)]
#[schema(value_type = String, format = Binary)]
pub struct Bytes(Vec<u8>);

#[utoipa::path(get, path = "/status", operation_id = "status", tag = "session", description = "Server name, version and whether first-run setup is pending. No sign-in needed.", responses((status = 200, description = "OK", body = Status), (status = 400, description = "Bad request", body = Error), (status = 429, description = "Too many attempts", body = Error), (status = 404, description = "No such item", body = Error)))]
fn status() {}

#[utoipa::path(post, path = "/setup", operation_id = "setup", tag = "session", description = "Create the first admin account with the code printed at startup. No sign-in needed.", request_body = SetupBody, responses((status = 200, description = "OK", body = Me), (status = 400, description = "Bad request", body = Error), (status = 429, description = "Too many attempts", body = Error), (status = 404, description = "No such item", body = Error)))]
fn setup() {}

#[utoipa::path(post, path = "/auth/login", operation_id = "login", tag = "session", description = "Sign in with a username and password. Sets the session cookie, unless the account has a second factor: then the answer holds a `pending` token for `POST /auth/login/totp` and no cookie is set. No sign-in needed.", request_body = LoginBody, responses((status = 200, description = "A session (cookie set), or `second_factor` and `pending` when the account has a second factor: no session exists until `POST /auth/login/totp`", body = LoginReply), (status = 400, description = "Bad request", body = Error), (status = 429, description = "Too many attempts", body = Error), (status = 404, description = "No such item", body = Error)))]
fn login() {}

#[utoipa::path(post, path = "/auth/login/totp", operation_id = "login_totp", tag = "session", description = "Finish a sign-in that asked for a second factor: the `pending` token and a TOTP code (or an unused recovery code). Each code works once; wrong codes count against the sign-in limits (429 with Retry-After). No sign-in needed.", request_body = TotpLoginBody, responses((status = 200, description = "OK", body = Me), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Wrong code, or the pending sign-in expired", body = Error), (status = 429, description = "Too many attempts", body = Error), (status = 404, description = "No such item", body = Error)))]
fn login_totp() {}

#[utoipa::path(post, path = "/auth/logout", operation_id = "logout", tag = "session", description = "End the current session. Needs the viewer role or above.", responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn logout() {}

#[utoipa::path(get, path = "/auth/me", operation_id = "me", tag = "session", description = "The signed-in user and the CSRF token for cookie sessions. Needs the viewer role or above.", responses((status = 200, description = "OK", body = Me), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn me() {}

#[utoipa::path(post, path = "/auth/ticket", operation_id = "login_ticket", tag = "session", description = "Exchange the single-use, 60-second login ticket of an embedded engine (`bosun serve --embedded`) for an admin session. Loopback only; the exchange is audited. No sign-in needed.", request_body = TicketBody, responses((status = 200, description = "OK", body = Me), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Ticket not valid", body = Error), (status = 429, description = "Too many attempts", body = Error), (status = 404, description = "No such item", body = Error)))]
fn login_ticket() {}

#[utoipa::path(get, path = "/auth/sso", operation_id = "sso_config", tag = "session", description = "Single sign-on button details, if configured. No sign-in needed.", responses((status = 200, description = "OK", body = SsoInfo), (status = 400, description = "Bad request", body = Error), (status = 429, description = "Too many attempts", body = Error), (status = 404, description = "No such item", body = Error)))]
fn sso_config() {}

#[utoipa::path(post, path = "/auth/password", operation_id = "change_password", tag = "session", description = "Change your own password. Needs the viewer role or above.", request_body = PasswordBody, responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn change_password() {}

#[utoipa::path(get, path = "/auth/totp", operation_id = "totp_status", tag = "session", description = "Your own second-factor state. Needs the viewer role or above.", responses((status = 200, description = "OK", body = TotpStatus), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn totp_status() {}

#[utoipa::path(post, path = "/auth/totp/enroll", operation_id = "totp_enroll", tag = "session", description = "Make a TOTP secret for your account (base32 and an `otpauth://` URI). Nothing asks for a code until `POST /auth/totp/confirm` receives a valid one; enrolling again before that replaces the secret. 409 when a second factor is already on. Audited. Needs the viewer role or above.", responses((status = 200, description = "OK", body = TotpEnrolment), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 409, description = "Already set up", body = Error)))]
fn totp_enroll() {}

#[utoipa::path(post, path = "/auth/totp/confirm", operation_id = "totp_confirm", tag = "session", description = "Turn the second factor on with the first valid code, and get ten one-time recovery codes (shown once). Audited. Needs the viewer role or above.", request_body = TotpCodeBody, responses((status = 200, description = "OK", body = RecoveryCodes), (status = 400, description = "Wrong code, or no enrolment in progress", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 409, description = "Already set up", body = Error), (status = 429, description = "Too many attempts", body = Error)))]
fn totp_confirm() {}

#[utoipa::path(post, path = "/auth/totp/disable", operation_id = "totp_disable", tag = "session", description = "Turn your own second factor off. Needs a valid code or an unused recovery code. Audited. Needs the viewer role or above.", request_body = TotpCodeBody, responses((status = 204, description = "Done"), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Wrong code, or not allowed", body = Error), (status = 429, description = "Too many attempts", body = Error)))]
fn totp_disable() {}

#[utoipa::path(post, path = "/auth/totp/recovery-codes", operation_id = "totp_recovery_codes", tag = "session", description = "Make a new set of ten recovery codes; the old ones stop working. Needs a valid code or an unused recovery code. Audited. Needs the viewer role or above.", request_body = TotpCodeBody, responses((status = 200, description = "OK", body = RecoveryCodes), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Wrong code, or not allowed", body = Error), (status = 429, description = "Too many attempts", body = Error)))]
fn totp_recovery_codes() {}

#[utoipa::path(put, path = "/auth/totp/required", operation_id = "totp_set_required", tag = "accounts", description = "Require a second factor of every password account (single sign-on accounts and the desktop ticket are not asked). Accounts without one can then only reach the pages that set it up. Audited. Needs the admin role.", request_body = TotpRequiredBody, responses((status = 200, description = "OK", body = TotpStatus), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn totp_set_required() {}

#[utoipa::path(delete, path = "/users/{id}/totp", operation_id = "reset_user_totp", tag = "accounts", description = "Remove a user's second factor and recovery codes (a lost device) and end their sessions. Audited. Needs the admin role.", params(("id" = i64, Path, description = "User id")), responses((status = 204, description = "Done"), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "That user has no second factor", body = Error)))]
fn reset_user_totp() {}

#[utoipa::path(get, path = "/flows", operation_id = "list_flows", tag = "history", description = "List recorded flows, newest first unless sorted. Needs the viewer role or above.", params(("text" = Option<String>, Query), ("host" = Option<String>, Query), ("methods" = Option<String>, Query), ("status_min" = Option<i64>, Query), ("status_max" = Option<i64>, Query), ("in_scope_only" = Option<bool>, Query), ("source" = Option<String>, Query), ("hide_ext" = Option<String>, Query), ("before" = Option<i64>, Query), ("after" = Option<i64>, Query), ("limit" = Option<i64>, Query), ("sort" = Option<String>, Query, description = "id (default), time, method, host, path, status, size, duration or mime. Ties break on the id."), ("asc" = Option<bool>, Query, description = "Oldest or smallest first."), ("offset" = Option<i64>, Query, description = "Rows to skip, for paging a list sorted by something other than id."), ("q" = Option<String>, Query, description = "A history query (docs/query-language.md), combined with the other filters by and. A mistake in it is a 400.")), responses((status = 200, description = "OK", body = Vec<FlowSummary>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn list_flows() {}

#[utoipa::path(get, path = "/flows/query", operation_id = "check_flow_query", tag = "history", description = "Check a history query without running it: the recognised terms with their positions, and every mistake. Needs the viewer role or above.", params(("q" = Option<String>, Query)), responses((status = 200, description = "OK", body = QueryCheck), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn check_flow_query() {}

#[utoipa::path(post, path = "/flows/tags", operation_id = "change_tags", tag = "history", description = "Add and remove tags on many flows in one step (tags compare without regard to case; a flow keeps at most 32). Answers how many flows changed. Needs the tester role or above.", request_body = ChangeTags, responses((status = 200, description = "OK", body = ChangedCount), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn change_tags() {}

#[utoipa::path(get, path = "/organizer", operation_id = "list_organizer", tag = "organizer", description = "Requests kept for follow-up, newest first, each with its status, note and the flow's summary. Needs the viewer role or above.", responses((status = 200, description = "OK", body = Vec<bosun_store::OrganizerItem>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn list_organizer() {}

#[utoipa::path(post, path = "/organizer", operation_id = "add_to_organizer", tag = "organizer", description = "Keep requests in the Organizer (ones already there are left alone). Answers how many were new. Needs the tester role or above.", request_body = OrganizerAdd, responses((status = 200, description = "OK", body = AddedCount), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn add_to_organizer() {}

#[utoipa::path(patch, path = "/organizer/{id}", operation_id = "update_organizer_item", tag = "organizer", description = "Change an item's status and/or note. Needs the tester role or above.", params(("id" = i64, Path)), request_body = OrganizerChange, responses((status = 204, description = "Changed"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn update_organizer_item() {}

#[utoipa::path(delete, path = "/organizer/{id}", operation_id = "delete_organizer_item", tag = "organizer", description = "Remove an item (the request stays in the history). Needs the tester role or above.", params(("id" = i64, Path)), responses((status = 204, description = "Removed"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn delete_organizer_item() {}

#[utoipa::path(get, path = "/saved-filters", operation_id = "get_saved_filters", tag = "history", description = "The project's saved history filters. Needs the viewer role or above.", responses((status = 200, description = "OK", body = Vec<SavedFilter>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn get_saved_filters() {}

#[utoipa::path(put, path = "/saved-filters", operation_id = "put_saved_filters", tag = "history", description = "Replace the saved filters. Every query must be valid. Needs the tester role or above.", request_body = Vec<SavedFilter>, responses((status = 200, description = "OK", body = Vec<SavedFilter>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn put_saved_filters() {}

#[utoipa::path(delete, path = "/flows", operation_id = "delete_flows", tag = "history", description = "Delete flows by id. Needs the tester role or above.", request_body = DeleteFlows, responses((status = 200, description = "OK", body = Deleted), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn delete_flows() {}

#[utoipa::path(get, path = "/flows/{id}", operation_id = "get_flow", tag = "history", description = "One flow without bodies. Needs the viewer role or above.", params(("id" = i64, Path)), responses((status = 200, description = "OK", body = FlowOverview), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn get_flow() {}

#[utoipa::path(patch, path = "/flows/{id}", operation_id = "annotate_flow", tag = "history", description = "Set tags and note. Needs the tester role or above.", params(("id" = i64, Path)), request_body = Annotate, responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn annotate_flow() {}

#[utoipa::path(get, path = "/flows/{id}/ws", operation_id = "ws_messages", tag = "history", description = "WebSocket messages of an upgraded flow. Needs the viewer role or above.", params(("id" = i64, Path), ("after" = Option<i64>, Query), ("limit" = Option<i64>, Query)), responses((status = 200, description = "OK", body = Vec<WsMessage>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn ws_messages() {}

#[utoipa::path(get, path = "/flows/{id}/{part}/body", operation_id = "flow_body", tag = "history", description = "A message body, streamed. Supports a single Range; ?decoded=1 undoes Content-Encoding (parts: request, response, original-request, original-response). Needs the viewer role or above.", params(("id" = i64, Path), ("part" = String, Path), ("decoded" = Option<String>, Query)), responses((status = 200, description = "Bytes", body = Bytes, content_type = "application/octet-stream"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn flow_body() {}

#[utoipa::path(get, path = "/sitemap", operation_id = "site_map", tag = "history", description = "Distinct hosts and paths seen. Needs the viewer role or above.", params(("host" = Option<String>, Query)), responses((status = 200, description = "OK", body = Vec<SiteMapEntry>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn site_map() {}

#[utoipa::path(get, path = "/scope", operation_id = "get_scope", tag = "scope", description = "The target scope. Needs the viewer role or above.", responses((status = 200, description = "OK", body = ScopeSpec), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn get_scope() {}

#[utoipa::path(put, path = "/scope", operation_id = "put_scope", tag = "scope", description = "Replace the target scope (audited). Needs the tester role or above.", request_body = ScopeSpec, responses((status = 200, description = "OK", body = ScopeSpec), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn put_scope() {}

#[utoipa::path(get, path = "/rules", operation_id = "get_rules", tag = "rules", description = "Match and replace rules. Needs the viewer role or above.", responses((status = 200, description = "OK", body = Vec<MatchRule>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn get_rules() {}

#[utoipa::path(put, path = "/rules", operation_id = "put_rules", tag = "rules", description = "Replace the rules (audited). Needs the tester role or above.", request_body = Vec<MatchRule>, responses((status = 200, description = "OK", body = Vec<MatchRule>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn put_rules() {}

#[utoipa::path(get, path = "/intercept", operation_id = "get_intercept", tag = "intercept", description = "Interception settings. Needs the viewer role or above.", responses((status = 200, description = "OK", body = InterceptSettings), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn get_intercept() {}

#[utoipa::path(put, path = "/intercept", operation_id = "put_intercept", tag = "intercept", description = "Change interception settings. Needs the tester role or above.", request_body = InterceptSettings, responses((status = 200, description = "OK", body = InterceptSettings), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn put_intercept() {}

#[utoipa::path(get, path = "/intercept/response-filter", operation_id = "get_response_filter", tag = "intercept", description = "Which responses are held when response interception is on. Needs the viewer role or above.", responses((status = 200, description = "OK", body = ResponseFilter), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn get_response_filter() {}

#[utoipa::path(put, path = "/intercept/response-filter", operation_id = "put_response_filter", tag = "intercept", description = "Change which responses are held (audited). Needs the tester role or above.", request_body = ResponseFilter, responses((status = 200, description = "OK", body = ResponseFilter), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn put_response_filter() {}

#[utoipa::path(get, path = "/intercept/queue", operation_id = "intercept_queue", tag = "intercept", description = "Held messages. Needs the viewer role or above.", responses((status = 200, description = "OK", body = Vec<InterceptSummary>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn intercept_queue() {}

#[utoipa::path(get, path = "/intercept/queue/{id}", operation_id = "intercept_item", tag = "intercept", description = "One held message. Needs the viewer role or above.", params(("id" = i64, Path)), responses((status = 200, description = "OK", body = InterceptItem), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn intercept_item() {}

#[utoipa::path(post, path = "/intercept/queue/{id}", operation_id = "intercept_decide", tag = "intercept", description = "Forward (optionally edited) or drop a held message. Needs the tester role or above.", params(("id" = i64, Path)), request_body = Decision, responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn intercept_decide() {}

#[utoipa::path(post, path = "/intercept/forward-all", operation_id = "intercept_forward_all", tag = "intercept", description = "Forward everything held. Needs the tester role or above.", responses((status = 200, description = "OK", body = Forwarded), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn intercept_forward_all() {}

#[utoipa::path(get, path = "/proxy", operation_id = "proxy_info", tag = "proxy", description = "Proxy settings and resource counters. Needs the viewer role or above.", responses((status = 200, description = "OK", body = ProxyInfo), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn proxy_info() {}

#[utoipa::path(put, path = "/tools/stop", operation_id = "set_stopped", tag = "proxy", description = "The kill switch for all tool traffic. Needs the tester role or above.", request_body = StopBody, responses((status = 200, description = "OK", body = Stopped), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn set_stopped() {}

#[utoipa::path(get, path = "/ca", operation_id = "ca_info", tag = "proxy", description = "The CA certificate's fingerprints and PEM. Needs the viewer role or above.", responses((status = 200, description = "OK", body = CaInfo), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn ca_info() {}

#[utoipa::path(get, path = "/ca/cert.pem", operation_id = "ca_pem", tag = "proxy", description = "The CA certificate for download. Needs the viewer role or above.", responses((status = 200, description = "Bytes", body = Bytes, content_type = "application/octet-stream"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn ca_pem() {}

#[utoipa::path(post, path = "/browser/launch", operation_id = "launch_browser", tag = "proxy", description = "Start a browser preconfigured for the proxy (loopback servers only). Needs the tester role or above.", responses((status = 200, description = "OK", body = Launched), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn launch_browser() {}

#[utoipa::path(get, path = "/tokens", operation_id = "list_tokens", tag = "accounts", description = "Your API tokens. Needs the viewer role or above.", responses((status = 200, description = "OK", body = Vec<ApiToken>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn list_tokens() {}

#[utoipa::path(post, path = "/tokens", operation_id = "create_token", tag = "accounts", description = "Create an API token; the secret is shown once. Needs the viewer role or above.", request_body = NewToken, responses((status = 201, description = "OK", body = NewTokenReply), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn create_token() {}

#[utoipa::path(delete, path = "/tokens/{id}", operation_id = "delete_token", tag = "accounts", description = "Revoke one of your tokens. Needs the viewer role or above.", params(("id" = i64, Path)), responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn delete_token() {}

#[utoipa::path(get, path = "/users", operation_id = "list_users", tag = "accounts", description = "All users. Needs the admin role or above.", responses((status = 200, description = "OK", body = Vec<User>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn list_users() {}

#[utoipa::path(post, path = "/users", operation_id = "create_user", tag = "accounts", description = "Create a user. Needs the admin role or above.", request_body = NewUser, responses((status = 201, description = "OK", body = User), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn create_user() {}

#[utoipa::path(delete, path = "/users/{id}", operation_id = "delete_user", tag = "accounts", description = "Delete a user. Needs the admin role or above.", params(("id" = i64, Path)), responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn delete_user() {}

#[utoipa::path(put, path = "/users/{id}/role", operation_id = "set_user_role", tag = "accounts", description = "Change a user's role. Needs the admin role or above.", params(("id" = i64, Path)), request_body = RoleBody, responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn set_user_role() {}

#[utoipa::path(get, path = "/users/{id}/sessions", operation_id = "list_user_sessions", tag = "accounts", description = "A user's sessions. Needs the admin role or above.", params(("id" = i64, Path)), responses((status = 200, description = "OK", body = Vec<SessionInfo>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn list_user_sessions() {}

#[utoipa::path(delete, path = "/users/{id}/sessions", operation_id = "revoke_user_sessions", tag = "accounts", description = "End all of a user's sessions. Needs the admin role or above.", params(("id" = i64, Path)), responses((status = 200, description = "OK", body = Revoked), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn revoke_user_sessions() {}

#[utoipa::path(delete, path = "/users/{id}/sessions/{sid}", operation_id = "revoke_user_session", tag = "accounts", description = "End one session. Needs the admin role or above.", params(("id" = i64, Path), ("sid" = String, Path)), responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn revoke_user_session() {}

#[utoipa::path(get, path = "/users/{id}/tokens", operation_id = "list_user_tokens", tag = "accounts", description = "A user's API tokens. Needs the admin role or above.", params(("id" = i64, Path)), responses((status = 200, description = "OK", body = Vec<ApiToken>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn list_user_tokens() {}

#[utoipa::path(delete, path = "/users/{id}/tokens/{tid}", operation_id = "revoke_user_token", tag = "accounts", description = "Revoke a user's token. Needs the admin role or above.", params(("id" = i64, Path), ("tid" = i64, Path)), responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn revoke_user_token() {}

#[utoipa::path(get, path = "/projects", operation_id = "list_projects", tag = "projects", description = "The projects in the projects folder, the one that is open, and recently opened names. Needs the viewer role or above.", responses((status = 200, description = "OK", body = ProjectList), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn list_projects() {}

#[utoipa::path(post, path = "/projects", operation_id = "create_project", tag = "projects", description = "Create a project, and open it if asked. Needs the admin role or above; audited.", request_body = NewProject, responses((status = 201, description = "Created", body = ProjectInfo), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn create_project() {}

#[utoipa::path(post, path = "/projects/close", operation_id = "close_project", tag = "projects", description = "Close the project: a temporary in-memory one opens in its place. Connected clients are told to reload. Needs the admin role or above; audited.", responses((status = 200, description = "OK", body = CurrentProject), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn close_project() {}

#[utoipa::path(post, path = "/projects/import", operation_id = "import_project", tag = "projects", description = "Import a project file sent as the request body (application/octet-stream). The file is never opened as it is: it is checked, then its content is copied into a new project. Needs the admin role or above; audited.", params(("name" = String, Query), ("open" = Option<bool>, Query)), responses((status = 201, description = "Created", body = ProjectInfo), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn import_project() {}

#[utoipa::path(delete, path = "/projects/{name}", operation_id = "delete_project", tag = "projects", description = "Delete a project that is not open. Needs the admin role or above; audited.", params(("name" = String, Path)), responses((status = 204, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn delete_project() {}

#[utoipa::path(post, path = "/projects/{name}/open", operation_id = "open_project", tag = "projects", description = "Switch to a project. Held intercept messages are dropped, interception starts off, and connected clients are told to reload. Needs the admin role or above; audited.", params(("name" = String, Path)), responses((status = 200, description = "OK", body = CurrentProject), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn open_project() {}

#[utoipa::path(post, path = "/projects/{name}/rename", operation_id = "rename_project", tag = "projects", description = "Rename a project that is not open. Needs the admin role or above; audited.", params(("name" = String, Path)), request_body = RenameProject, responses((status = 200, description = "OK", body = ProjectInfo), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn rename_project() {}

#[utoipa::path(get, path = "/projects/{name}/export", operation_id = "export_project", tag = "projects", description = "Download a consistent copy of a project (including the open one) as a file. Needs the admin role or above; audited.", params(("name" = String, Path)), responses((status = 200, description = "The project file", content_type = "application/octet-stream"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn export_project() {}

#[utoipa::path(post, path = "/projects/{name}/backup", operation_id = "backup_project", tag = "projects", description = "Save a copy of a project in the backups folder. Needs the admin role or above; audited.", params(("name" = String, Path)), responses((status = 200, description = "OK", body = BackupInfo), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Conflict (name taken, project locked or open)", body = Error)))]
fn backup_project() {}

#[utoipa::path(get, path = "/issues", operation_id = "list_issues", tag = "issues", description = "Issues the passive scanner found in recorded traffic, newest sighting first, with the number of flows it has not read yet. Filter by status, severity, confidence, rule, host, evidence flow or text. Needs the viewer role or above.", params(("status" = Option<String>, Query, description = "new, confirmed or false_positive"), ("severity" = Option<String>, Query, description = "info, low, medium or high"), ("confidence" = Option<String>, Query, description = "tentative, firm or certain"), ("rule" = Option<String>, Query), ("host" = Option<String>, Query), ("flow_id" = Option<i64>, Query), ("q" = Option<String>, Query, description = "Text in the title, detail or path"), ("limit" = Option<u32>, Query, description = "Up to 5000; default 1000")), responses((status = 200, description = "OK", body = IssueList), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn list_issues() {}
#[utoipa::path(post, path = "/issues/rescan", operation_id = "rescan_issues", tag = "issues", description = "Queue every recorded flow for the scanner again (after a rule changed). Counts start over; statuses are kept. Needs the tester role or above; audited.", responses((status = 204, description = "Queued"), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn rescan_issues() {}
#[utoipa::path(get, path = "/issues/{id}", operation_id = "get_issue", tag = "issues", description = "One issue with its evidence ranges and remediation. Needs the viewer role or above.", params(("id" = i64, Path, description = "Issue id")), responses((status = 200, description = "OK", body = bosun_store::Issue), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such issue", body = Error)))]
fn get_issue() {}
#[utoipa::path(patch, path = "/issues/{id}", operation_id = "change_issue", tag = "issues", description = "Set an issue's status (new, confirmed or false_positive). Needs the tester role or above; audited.", params(("id" = i64, Path, description = "Issue id")), request_body = IssueChange, responses((status = 204, description = "Changed"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such issue", body = Error)))]
fn change_issue() {}

#[utoipa::path(get, path = "/audit", operation_id = "audit_log", tag = "accounts", description = "The audit log, newest first. Needs the admin role or above.", params(("before" = Option<i64>, Query), ("limit" = Option<i64>, Query)), responses((status = 200, description = "OK", body = Vec<AuditEntry>), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn audit_log() {}

#[utoipa::path(get, path = "/flows/{id}/engage", operation_id = "flow_engage", tag = "history", description = "Comments, scripts, references and URLs in the response, and the parameters of the request, for finding what to test next. Scans up to 2 MiB of each body. Needs the viewer role.", params(("id" = i64, Path, description = "Flow id")), responses((status = 200, description = "OK", body = crate::engage::EngageReport), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such flow", body = Error)))]
fn flow_engage() {}

#[utoipa::path(get, path = "/analysis", operation_id = "host_analysis", tag = "history", description = "The distinct endpoints (ids in paths replaced by {n}, {uuid} and {hex}) and parameters of one host across the history, with counts, status codes and example values. Reads the newest 5,000 requests of the host (?limit up to 20,000); `capped` says there were more. Needs the viewer role.", params(("host" = String, Query, description = "Exact host name"), ("port" = Option<u16>, Query, description = "Only this port"), ("limit" = Option<u32>, Query, description = "How many of the newest requests to read")), responses((status = 200, description = "OK", body = crate::engage::HostAnalysis), (status = 400, description = "No host given", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn host_analysis() {}

#[utoipa::path(get, path = "/flows/{id}/csrf-poc", operation_id = "flow_csrf_poc", tag = "history", description = "A cross-site request forgery proof of concept for the recorded request, as an HTML attachment to open in a test browser that is signed in to the target. Only a GET or POST with a form, JSON-object or multipart body can be reproduced; anything else is a 422 that says why. ?auto=1 submits on load. Needs the viewer role.", params(("id" = i64, Path, description = "Flow id"), ("auto" = Option<String>, Query, description = "1 to submit on load")), responses((status = 200, description = "An HTML file", content_type = "text/html", body = String), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such flow", body = Error), (status = 422, description = "The request cannot be reproduced by a form", body = Error)))]
fn flow_csrf_poc() {}

#[utoipa::path(get, path = "/events", operation_id = "events", tag = "events", description = "WebSocket event stream. ?since=N&epoch=E resumes after event N of that engine run (see ProxyEvent). Needs the viewer role or above.", params(("since" = Option<i64>, Query), ("epoch" = Option<String>, Query)), responses((status = 101, description = "Done"), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn events() {}

#[utoipa::path(post, path = "/decoder/apply", operation_id = "decoder_apply", tag = "decoder", description = "Run a chain of up to 16 decoders or encoders (URL, HTML, Base64, hex, gzip, deflate, brotli, zstd, JWT, Unicode escapes, hashes) on base64 input. Returns each step's output (the last in full); a failing step is reported and the steps before it are still returned. Input and each output are limited to 4 MiB. Needs the viewer role.", request_body = DecodeBody, responses((status = 200, description = "OK", body = DecodeReply), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 413, description = "Input too large", body = Error)))]
fn decoder_apply() {}
#[utoipa::path(post, path = "/decoder/smart", operation_id = "decoder_smart", tag = "decoder", description = "Guess and apply a chain of decoders (up to 16 layers). Plain text is returned with no steps. Needs the viewer role.", request_body = SmartBody, responses((status = 200, description = "OK", body = DecodeReply), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 413, description = "Input too large", body = Error)))]
fn decoder_smart() {}
#[utoipa::path(post, path = "/comparer/diff", operation_id = "comparer_diff", tag = "decoder", description = "Compare two inputs (up to 1 MiB each, base64) by word or by byte. Returns runs of equal, deleted and inserted bytes with their offsets. Very different large inputs are reported coarsely. Needs the viewer role.", request_body = DiffBody, responses((status = 200, description = "OK", body = bosun_codec::DiffResult), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 413, description = "Input too large", body = Error)))]
fn comparer_diff() {}
#[utoipa::path(post, path = "/import", operation_id = "import_requests", tag = "repeater", description = "Import request definitions from an OpenAPI or Swagger file, a GraphQL introspection result, a Postman collection, a HAR file, a list of URLs or a Burp XML export, and save them as Repeater tabs. The file is only parsed: nothing is sent, and a tab is sent later through the Repeater, which passes the scope gate. Files over 32 MiB, YAML aliases, XML entities and deeply nested input are refused. The reply lists the hosts the requests go to. The import is audited. Needs the tester role or above.", request_body = crate::imports::ImportBody, responses((status = 200, description = "OK", body = crate::imports::ImportReply), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 413, description = "Too large", body = Error), (status = 422, description = "The file could not be imported", body = Error)))]
fn import_requests() {}
#[utoipa::path(post, path = "/repeater/send", operation_id = "repeater_send", tag = "repeater", description = "Send a raw request once or many times (sequentially, in parallel, or as an HTTP/2 single-packet batch). Every send passes the scope gate and is recorded as a flow with source repeater. A send that is refused or fails comes back as a result with an error, not as an HTTP error. Needs the tester role or above.", request_body = SendBody, responses((status = 200, description = "OK", body = SendReply), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn repeater_send() {}
#[utoipa::path(get, path = "/repeater/settings", operation_id = "get_repeater_settings", tag = "repeater", description = "Whether the Repeater may send out of scope.", responses((status = 200, description = "OK", body = RepeaterSettings), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn get_repeater_settings() {}
#[utoipa::path(put, path = "/repeater/settings", operation_id = "put_repeater_settings", tag = "repeater", description = "Allow or refuse out-of-scope sends from the Repeater (audited; goes back to refuse when a project is opened). Needs the tester role or above.", request_body = RepeaterSettings, responses((status = 200, description = "OK", body = RepeaterSettings), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn put_repeater_settings() {}
#[utoipa::path(get, path = "/repeater/tabs", operation_id = "get_repeater_tabs", tag = "repeater", description = "The Repeater's tabs as saved in the open project (requests and options; responses are not stored).", responses((status = 200, description = "OK", body = TabsDoc), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn get_repeater_tabs() {}
#[utoipa::path(post, path = "/repeater/ws", operation_id = "repeater_ws", tag = "repeater", description = "Open a WebSocket with a raw handshake, send frames exactly as described (any opcode, reserved bits, FIN and mask), listen for a while, then close. The handshake is recorded as a flow with source repeater and the frames as its messages. Passes the scope gate. A refused or failed connection comes back as a reply with an error. Needs the tester role or above.", request_body = WsBody, responses((status = 200, description = "OK", body = WsReply), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn repeater_ws() {}
#[utoipa::path(put, path = "/repeater/tabs", operation_id = "put_repeater_tabs", tag = "repeater", description = "Replace the Repeater's saved tabs (at most 500). Needs the tester role or above.", request_body = TabsDoc, responses((status = 200, description = "OK", body = TabsDoc), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 413, description = "Too large", body = Error)))]
fn put_repeater_tabs() {}
#[utoipa::path(post, path = "/sequencer/analyze", operation_id = "sequencer_analyze", tag = "sequencer", description = "Analyse how random a set of tokens is (20 to 10000, each up to 1024 characters): per-position character statistics, bit-level bias, FIPS 140-2 (monobit, poker, runs, long run) on blocks of 20000 bits, an entropy estimate, checks for repeats and counters, and a verdict (excellent, good, poor, not_random). The result is the export. Needs the viewer role.", request_body = AnalyzeBody, responses((status = 200, description = "OK", body = bosun_sequencer::Analysis), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn sequencer_analyze() {}
#[utoipa::path(post, path = "/sequencer/capture", operation_id = "sequencer_capture", tag = "sequencer", description = "Start collecting tokens: send a request up to 5000 times (one after another, with an optional pause) and take the token from a response header, a Set-Cookie cookie or a regular expression over the body. Every request passes the scope gate (scope, kill switch, per-host rate limit; a rate-limit refusal is waited out) through the Repeater's engine and is recorded as a flow with source repeater. At most two captures run at once. Poll /sequencer/capture/{id}. Needs the tester role or above.", request_body = CaptureBody, responses((status = 202, description = "Started", body = CaptureStarted), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 429, description = "Too many running", body = Error)))]
fn sequencer_capture() {}
#[utoipa::path(get, path = "/sequencer/capture/{id}", operation_id = "sequencer_capture_status", tag = "sequencer", description = "The progress of a capture and its tokens from index `from` on. Needs the viewer role.", params(("id" = u64, Path, description = "Capture id"), ("from" = Option<usize>, Query, description = "Return tokens from this index on")), responses((status = 200, description = "OK", body = CaptureStatus), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such capture", body = Error)))]
fn sequencer_capture_status() {}
#[utoipa::path(post, path = "/sequencer/capture/{id}/stop", operation_id = "sequencer_capture_stop", tag = "sequencer", description = "The stop switch: the capture ends after the request in flight. Needs the tester role or above.", params(("id" = u64, Path, description = "Capture id")), responses((status = 200, description = "OK", body = CaptureStatus), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such capture", body = Error)))]
fn sequencer_capture_stop() {}

#[utoipa::path(post, path = "/intruder/plan", operation_id = "intruder_plan", tag = "intruder", description = "Check an attack without sending anything: the request's positions, the payload sets, the options and the grep rules are validated, and the number of requests and the first few payloads come back. A problem is a 400 that says what. Needs the tester role or above.", request_body = StartBody, responses((status = 200, description = "OK", body = PlanReply), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error)))]
fn intruder_plan() {}
#[utoipa::path(post, path = "/intruder/attacks", operation_id = "intruder_start", tag = "intruder", description = "Start an attack: fill the marked positions of a request with payloads (sniper, battering ram, pitchfork or cluster bomb) and send every request through the scope gate (the target must be in scope; there is no out-of-scope setting), recorded as flows with source intruder. Results are stored in the project and sent on the event stream (intruder_result, intruder_state). Up to three attacks run at once. Needs the tester role or above; audited.", request_body = StartBody, responses((status = 200, description = "The attack, running", body = AttackInfo), (status = 400, description = "Bad request", body = Error), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such item", body = Error), (status = 409, description = "Too many attacks running or stored", body = Error)))]
fn intruder_start() {}
#[utoipa::path(get, path = "/intruder/attacks", operation_id = "intruder_attacks", tag = "intruder", description = "The project's attacks, newest first, with live progress for running ones.", responses((status = 200, description = "OK", body = AttackList), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error)))]
fn intruder_attacks() {}
#[utoipa::path(get, path = "/intruder/attacks/{id}", operation_id = "intruder_attack", tag = "intruder", description = "One attack, with its request (position markers included) and the configuration it was started with.", params(("id" = i64, Path, description = "Attack id")), responses((status = 200, description = "OK", body = AttackDetail), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such attack", body = Error)))]
fn intruder_attack() {}
#[utoipa::path(delete, path = "/intruder/attacks/{id}", operation_id = "intruder_delete", tag = "intruder", description = "Delete an attack and its results (the flows it recorded stay in history). A running attack is a 409. Needs the tester role or above; audited.", params(("id" = i64, Path, description = "Attack id")), responses((status = 204, description = "Deleted"), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such attack", body = Error), (status = 409, description = "The attack is running", body = Error)))]
fn intruder_delete() {}
#[utoipa::path(get, path = "/intruder/attacks/{id}/results", operation_id = "intruder_results", tag = "intruder", description = "An attack's results in request order, up to 5000 per page (?offset and ?limit).", params(("id" = i64, Path, description = "Attack id"), ("offset" = Option<i64>, Query), ("limit" = Option<i64>, Query)), responses((status = 200, description = "OK", body = ResultsReply), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such attack", body = Error)))]
fn intruder_results() {}
#[utoipa::path(post, path = "/intruder/attacks/{id}/stop", operation_id = "intruder_stop", tag = "intruder", description = "The stop switch: no further request is sent and the ones in flight are dropped, at once. `stopped` is false when the attack was not running. (The kill switch, PUT /tools/stop, ends every attack too.) Needs the tester role or above; audited.", params(("id" = i64, Path, description = "Attack id")), responses((status = 200, description = "OK", body = StopReply), (status = 401, description = "Not signed in", body = Error), (status = 403, description = "Not allowed", body = Error), (status = 404, description = "No such attack", body = Error)))]
fn intruder_stop() {}

#[derive(OpenApi)]
#[openapi(
    info(title = "Bosun API", version = env!("CARGO_PKG_VERSION"),
        description = "Local API of the Bosun engine. Sign in with a session cookie (send the CSRF token on changes) or an API token (`Authorization: Bearer bosun_…`)."),
    paths(status, setup, login, login_totp, logout, me, login_ticket, sso_config, change_password, totp_status, totp_enroll, totp_confirm, totp_disable, totp_recovery_codes, totp_set_required, reset_user_totp, list_flows, check_flow_query, change_tags, list_organizer, add_to_organizer, update_organizer_item, delete_organizer_item, get_saved_filters, put_saved_filters, delete_flows, get_flow, annotate_flow, ws_messages, flow_body, flow_engage, flow_csrf_poc, host_analysis, site_map, get_scope, put_scope, get_rules, put_rules, get_intercept, put_intercept, get_response_filter, put_response_filter, intercept_queue, intercept_item, intercept_decide, intercept_forward_all, proxy_info, set_stopped, decoder_apply, decoder_smart, comparer_diff, import_requests, repeater_send, get_repeater_settings, put_repeater_settings, get_repeater_tabs, put_repeater_tabs, repeater_ws, intruder_plan, intruder_start, intruder_attacks, intruder_attack, intruder_delete, intruder_results, intruder_stop, list_issues, rescan_issues, get_issue, change_issue, sequencer_analyze, sequencer_capture, sequencer_capture_status, sequencer_capture_stop, ca_info, ca_pem, launch_browser, list_tokens, create_token, delete_token, list_users, create_user, delete_user, set_user_role, list_user_sessions, revoke_user_sessions, revoke_user_session, list_user_tokens, revoke_user_token, list_projects, create_project, close_project, import_project, delete_project, open_project, rename_project, export_project, backup_project, audit_log, events),
    components(schemas(crate::imports::ImportBody, crate::imports::ImportReply, bosun_import::Format, ResponseFilter, bosun_store::Issue, bosun_store::Severity, bosun_store::Confidence, bosun_store::IssueStatus, bosun_store::Evidence, bosun_store::EvidencePart, LoginReply, SecondFactor, TotpStatus, TotpEnrolment, RecoveryCodes, crate::engage::EngageReport, crate::engage::HostAnalysis, bosun_codec::engage::TargetAnalysis, bosun_codec::engage::EndpointStat, bosun_codec::engage::StatusCount, bosun_codec::engage::ParamStat, bosun_codec::engage::Finding, bosun_codec::engage::FindingKind, bosun_codec::engage::Param, bosun_codec::engage::ParamWhere, OrganizerAdd, OrganizerChange, AddedCount, bosun_store::OrganizerItem, bosun_store::OrganizerStatus, ChangeTags, ChangedCount, QueryCheck, SavedFilter, bosun_store::query::TermSpan, bosun_store::query::QueryError, ProjectInfo, CurrentProject, ProjectList, NewProject, RenameProject, BackupInfo, ProxyEvent, FlowMeta, FlowSummary, WsMessage, InterceptItem, InterceptSummary, Decision)),
    tags((name = "session"), (name = "history"), (name = "scope"), (name = "rules"), (name = "intercept"), (name = "proxy"), (name = "repeater"), (name = "decoder"), (name = "intruder"), (name = "issues"), (name = "sequencer"), (name = "accounts"), (name = "projects"), (name = "events"))
)]
pub struct Api;

/// The description as pretty JSON, the form committed in `docs/openapi.json`.
pub fn json() -> String {
    let mut s = Api::openapi()
        .to_pretty_json()
        .expect("the description serialises");
    s.push('\n');
    s
}

/// Every documented (method, path), for checking against the router.
pub const OPERATIONS: &[(&str, &str)] = &[
    ("get", "/status"),
    ("post", "/setup"),
    ("post", "/auth/login"),
    ("post", "/auth/logout"),
    ("get", "/auth/me"),
    ("post", "/auth/ticket"),
    ("get", "/auth/sso"),
    ("post", "/auth/password"),
    ("post", "/auth/login/totp"),
    ("get", "/auth/totp"),
    ("post", "/auth/totp/enroll"),
    ("post", "/auth/totp/confirm"),
    ("post", "/auth/totp/disable"),
    ("post", "/auth/totp/recovery-codes"),
    ("put", "/auth/totp/required"),
    ("delete", "/users/{id}/totp"),
    ("get", "/flows"),
    ("get", "/flows/query"),
    ("post", "/flows/tags"),
    ("get", "/organizer"),
    ("post", "/organizer"),
    ("patch", "/organizer/{id}"),
    ("delete", "/organizer/{id}"),
    ("get", "/saved-filters"),
    ("put", "/saved-filters"),
    ("delete", "/flows"),
    ("get", "/flows/{id}"),
    ("patch", "/flows/{id}"),
    ("get", "/flows/{id}/ws"),
    ("get", "/flows/{id}/engage"),
    ("get", "/flows/{id}/csrf-poc"),
    ("get", "/analysis"),
    ("get", "/flows/{id}/{part}/body"),
    ("get", "/sitemap"),
    ("get", "/scope"),
    ("put", "/scope"),
    ("get", "/rules"),
    ("put", "/rules"),
    ("get", "/intercept"),
    ("put", "/intercept"),
    ("get", "/intercept/response-filter"),
    ("put", "/intercept/response-filter"),
    ("get", "/intercept/queue"),
    ("get", "/intercept/queue/{id}"),
    ("post", "/intercept/queue/{id}"),
    ("post", "/intercept/forward-all"),
    ("get", "/proxy"),
    ("put", "/tools/stop"),
    ("post", "/decoder/apply"),
    ("post", "/decoder/smart"),
    ("post", "/comparer/diff"),
    ("post", "/import"),
    ("post", "/repeater/send"),
    ("get", "/repeater/settings"),
    ("put", "/repeater/settings"),
    ("post", "/repeater/ws"),
    ("get", "/repeater/tabs"),
    ("put", "/repeater/tabs"),
    ("post", "/sequencer/analyze"),
    ("post", "/sequencer/capture"),
    ("get", "/sequencer/capture/{id}"),
    ("post", "/sequencer/capture/{id}/stop"),
    ("post", "/intruder/plan"),
    ("post", "/intruder/attacks"),
    ("get", "/intruder/attacks"),
    ("get", "/intruder/attacks/{id}"),
    ("delete", "/intruder/attacks/{id}"),
    ("get", "/intruder/attacks/{id}/results"),
    ("post", "/intruder/attacks/{id}/stop"),
    ("get", "/ca"),
    ("get", "/ca/cert.pem"),
    ("post", "/browser/launch"),
    ("get", "/tokens"),
    ("post", "/tokens"),
    ("delete", "/tokens/{id}"),
    ("get", "/users"),
    ("post", "/users"),
    ("delete", "/users/{id}"),
    ("put", "/users/{id}/role"),
    ("get", "/users/{id}/sessions"),
    ("delete", "/users/{id}/sessions"),
    ("delete", "/users/{id}/sessions/{sid}"),
    ("get", "/users/{id}/tokens"),
    ("delete", "/users/{id}/tokens/{tid}"),
    ("get", "/projects"),
    ("post", "/projects"),
    ("post", "/projects/close"),
    ("post", "/projects/import"),
    ("delete", "/projects/{name}"),
    ("post", "/projects/{name}/open"),
    ("post", "/projects/{name}/rename"),
    ("get", "/projects/{name}/export"),
    ("post", "/projects/{name}/backup"),
    ("get", "/issues"),
    ("post", "/issues/rescan"),
    ("get", "/issues/{id}"),
    ("patch", "/issues/{id}"),
    ("get", "/audit"),
    ("get", "/events"),
];
