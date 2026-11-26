# History query language

One line of text that filters the recorded history. The server parses it (`bosun_store::query`), so the UI, the
CLI and plugins all mean the same thing by it. Use it as `GET /api/v1/flows?q=...`; `GET /api/v1/flows/query?q=...`
only checks a query and says what each part means.

```
host:example.com method:GET,POST status:4xx -ext:png,css (login or "sign in") header:x-api-key size:>10k
```

## Grammar

```
query  = or
or     = and { "or" and }
and    = unary { ["and"] unary }          terms next to each other are joined by "and"
unary  = [ "not" | "-" ] ( "(" or ")" | term )
term   = key ":" value | text
text   = word | "quoted words"
```

- `and` binds tighter than `or`: `a or b c` means `a or (b and c)`. Use parentheses to change that.
- `not x`, `-x` and `-(...)` negate a term or a group. A flow with no status counts as *not* `status:4xx`.
- `or`, `and` and `not` are keywords only when written bare; `"or"` in quotes is the word.
- A word that is not `key:value`, or whose key is unknown, is free text, so `http://x.test/a` can be searched for.
- Keys and keywords are case-insensitive.
- Within a value, a comma means "or": `method:GET,POST`, `host:a.com,b.com`, `status:404,5xx`.

## Terms

| Term | Matches |
|---|---|
| `text`, `"two words"` | Request line, headers and text bodies (a trigram index: needs three or more characters; shorter text is looked for in the host and path). Case-insensitive. |
| `host:` (`h:`) | Host contains the text. A leading `https://` is ignored. |
| `method:` (`m:`) | Method is one of the names (any case). |
| `status:` (`s:`) | `404`, `4xx`, `400-499`, `>=400`, `>399`, `<500`, `<=500`. |
| `scope:in`, `scope:out` | In or out of scope. |
| `ext:` | Path ends in the extension(s), letters and digits only: `-ext:png,css` hides them. |
| `source:` | Where the flow came from: `proxy`, `repeater`, `intruder`, ... |
| `header:name` | The header appears in the request or the response. `header:name=value` also needs the value. Two or more characters in the name. |
| `tag:` | The flow has this tag (case-insensitive). |
| `note:` | The note contains the text. |
| `has:` | `note`, `error`, `edited` or `response`. |
| `mime:` | Response type contains the text, such as `mime:json`. |
| `path:` | Path (with query string) contains the text. |
| `port:`, `scheme:` | A port number; `http` or `https`. |
| `size:` | Response size in bytes, with `k`, `m` or `g`: `>10k`, `<=2m`, `500`, `1k-1m`. |
| `since:`, `until:` | Started at or after, or at or before: `30s`, `10m`, `2h`, `7d` (ago) or a date such as `2026-11-25` (UTC). |

`header:` and free text both search the one text index, so `header:name` also finds the same words in a body.

## Mistakes

A mistake in a term is reported with its position and the term is left out; the rest of the query still applies.
`GET /flows?q=` answers 400 with the first mistake; `GET /flows/query?q=` lists them all, with the recognised
terms (`key`, `label`, `start`, `end`) so a front end can draw chips and underline the error.

## Saved filters

`GET /api/v1/saved-filters` lists the project's saved filters (`name`, `query`); `PUT` replaces the list (tester role).
Up to 50, names of 1 to 60 characters, no duplicates, and every query must parse without a mistake, so a saved filter
always runs. They live in the project's settings, so they travel with a project export. The History bar lists them under
"Saved", keeps the last 25 lines you applied under "Recent" (in the browser only), and completes keys and common values
as you type (Tab or Enter takes a suggestion).

## Limits

2,000 characters, 64 terms, 8 levels of parentheses. A query that runs for more than five seconds is stopped and
answers 400, and results are capped like any other listing (`limit`, at most 5,000). The query is only ever
turned into an SQL condition with bound parameters; none of its text becomes part of the SQL. `fuzz/fuzz_targets/history_query.rs`
fuzzes the parser and runs what it produces against a real project.
