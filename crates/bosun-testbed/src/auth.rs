//! The logged-in area: a login form, per-user orders, and two planted access-control bugs (with safe twins).
//!
//! - `POST /login` (`user=`, `pass=`) sets `sid=` and redirects to `/app`; users are `alice`/`alicepw`,
//!   `bob`/`bobpw` and `admin`/`adminpw`. `POST /logout` ends the session; `POST /auth/expire` ends every one (a
//!   test hook for re-authentication).
//! - `GET /app` greets the user, or redirects to `/login` without a session.
//! - `GET /app/orders/{id}`: orders 1 and 2 are alice's, 3 and 4 are bob's. Any signed-in user can read any (IDOR);
//!   `/app/orders-safe/{id}` checks the owner.
//! - `GET /app/admin/users`: needs a session but not the admin role (vertical bypass); `/app/admin-safe/users`
//!   checks the role.
//! - `GET /api/token` returns a bearer token for a session; `GET /api/me` accepts `Authorization: Bearer`.

use super::{Reply, Rq, State, html};

const USERS: &[(&str, &str)] = &[("alice", "alicepw"), ("bob", "bobpw"), ("admin", "adminpw")];
const ORDERS: &[(u32, &str, &str)] = &[
    (1, "alice", "2 x anchor chain"),
    (2, "alice", "1 x sextant"),
    (3, "bob", "40 m of rope"),
    (4, "bob", "1 x brass bell"),
];

fn form(body: &str, key: &str) -> String {
    super::param(body, key)
}

/// The user a request is signed in as, from the `sid` cookie or a bearer token.
fn user_of(rq: &Rq<'_>, st: &State) -> Option<String> {
    let cookie = rq.header("cookie");
    let sid = cookie
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == "sid")
        .map(|(_, v)| v.to_string())
        .or_else(|| {
            rq.header("authorization")
                .strip_prefix("Bearer ")
                .map(str::to_string)
        })?;
    sessions(st)
        .iter()
        .find(|(t, _)| *t == sid)
        .map(|(_, u)| u.clone())
}

fn sessions(st: &State) -> std::sync::MutexGuard<'_, Vec<(String, String)>> {
    st.sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn login_required() -> Reply {
    Reply::new(302, "text/html", "login required").header("Location: /login")
}

fn login(rq: &Rq<'_>, st: &State) -> Reply {
    let (u, p) = (form(rq.body, "user"), form(rq.body, "pass"));
    if !USERS.iter().any(|(n, pw)| *n == u && *pw == p) {
        return Reply::new(401, "text/html", "bad credentials");
    }
    let n = st.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sid = format!("s{n:x}{:x}", u.len() * 7919 + n as usize * 104729);
    sessions(st).push((sid.clone(), u));
    Reply::new(302, "text/html", "ok")
        .header(format!("Set-Cookie: sid={sid}; Path=/; HttpOnly"))
        .header("Location: /app")
}

fn orders(rq: &Rq<'_>, st: &State, id: &str, check_owner: bool) -> Reply {
    let Some(me) = user_of(rq, st) else {
        return login_required();
    };
    let Some((_, owner, what)) = ORDERS.iter().find(|(i, ..)| id.parse() == Ok(*i)) else {
        return Reply::new(404, "text/html", "no such order");
    };
    if check_owner && *owner != me && me != "admin" {
        return Reply::new(403, "text/html", "forbidden");
    }
    html(&format!("Order {id} for {owner}: {what}"))
}

fn admin(rq: &Rq<'_>, st: &State, check_role: bool) -> Reply {
    let Some(me) = user_of(rq, st) else {
        return login_required();
    };
    if check_role && me != "admin" {
        return Reply::new(403, "text/html", "forbidden");
    }
    html("Users: alice, bob, admin")
}

pub fn route(rq: &Rq<'_>, st: &State) -> Option<Reply> {
    let path = rq.target.split_once('?').map_or(rq.target, |(p, _)| p);
    Some(match (rq.method, path) {
        ("GET", "/login") => {
            html("<form method=\"post\" action=\"/login\"><input name=\"user\"><input name=\"pass\"></form>")
        }
        ("POST", "/login") => login(rq, st),
        ("POST", "/logout") => {
            if let Some(me) = user_of(rq, st) {
                let cookie = rq.header("cookie");
                sessions(st).retain(|(t, u)| *u != me || !cookie.contains(t.as_str()));
            }
            Reply::new(302, "text/html", "bye").header("Location: /login")
        }
        ("POST", "/auth/expire") => {
            sessions(st).clear();
            html("expired")
        }
        ("GET", "/app") => match user_of(rq, st) {
            Some(u) => html(&format!("Welcome {u}")),
            None => login_required(),
        },
        ("GET", "/api/token") => match user_of(rq, st) {
            Some(_) => html(
                rq.header("cookie")
                    .split(';')
                    .filter_map(|c| c.trim().strip_prefix("sid="))
                    .next()
                    .unwrap_or(""),
            ),
            None => Reply::new(401, "text/html", "unauthorised"),
        },
        ("GET", "/api/me") => match user_of(rq, st) {
            Some(u) => Reply::new(200, "application/json", format!("{{\"user\":\"{u}\"}}")),
            None => Reply::new(401, "application/json", "{\"error\":\"unauthorised\"}"),
        },
        ("GET", p) if p.starts_with("/app/orders/") => orders(rq, st, &p[12..], false),
        ("GET", p) if p.starts_with("/app/orders-safe/") => orders(rq, st, &p[17..], true),
        ("GET", "/app/admin/users") => admin(rq, st, false),
        ("GET", "/app/admin-safe/users") => admin(rq, st, true),
        _ => return None,
    })
}
