# FileStorage — HTTP API (P1 + declared P2)


<!-- toc -->

- [P1 — Auth-required](#p1--auth-required)
- [P2 — Multipart upload (declared, not implemented in P1)](#p2--multipart-upload-declared-not-implemented-in-p1)
- [P2 — Versioning (when backend declares `versioning_native`)](#p2--versioning-when-backend-declares-versioning_native)
- [POST /files vs PATCH /files/{id}](#post-files-vs-patch-filesid)
- [Conditional headers](#conditional-headers)
- [Range support](#range-support)
- [Response headers (download + HEAD)](#response-headers-download--head)
- [Status code summary](#status-code-summary)

<!-- /toc -->

FileStorage issues exactly one shape of file URL: `/files/{file_id_uuid}` (`GET` / `HEAD` only), served only on the
auth-required prefix and reachable only with a valid platform JWT. FileStorage P1 has **no anonymous surface** —
anonymous/public access, time-bounded URLs, named recipients, download counters, and any other sharing primitives
are deferred to P3 (see DESIGN.md §1.1 "Sharing boundary"); whether they ship as a separate sibling gear or as
an extension of FileStorage is left to a future ADR.

Base URL:
- `/api/file-storage/v1` — JWT enforced by API Gateway; standard owner/tenant authorization applies

Encoding conventions:
- Multipart create/update bodies use `multipart/form-data` with two named parts: `metadata` (`application/json`) and `content` (binary, `Content-Type` = declared mime).
- All error responses follow RFC 7807 (`application/problem+json`).
- File ids are UUIDs.

## P1 — Auth-required

```
1.  POST   /files                              create   (multipart: metadata required + content required)
2.  PATCH  /files/{id}[?replace_content=true]  update   (multipart: metadata optional; content only with ?replace_content=true) — If-Match
3.  GET    /files/{id}                         download content                                              — If-Match, If-None-Match, Range
4.  HEAD   /files/{id}                         metadata headers                                              — If-Match, If-None-Match
5.  DELETE /files/{id}                         delete                                                        — If-Match
6.  GET    /files                              list (filters, paginated; JSON array of metadata)
7.  GET    /storages                           list storages + capabilities inline
8.  GET    /storages/{storage_id}              one storage + capabilities
```

## P2 — Multipart upload (declared, not implemented in P1)

```
9.  POST   /files/multipart                                      initiate (JSON metadata); returns {file_id, upload_id, etag}; creates pending file
10. POST   /files/{id}/multipart/{upload_id}/parts/{n}           upload one part (binary body)                                — If-Match
11. POST   /files/{id}/multipart/{upload_id}/complete            finalize; transitions file to available                     — If-Match
12. DELETE /files/{id}/multipart/{upload_id}                     abort; parts discarded                                       — If-Match
13. GET    /files/{id}/multipart/{upload_id}                     list uploaded parts (introspection)
```

## P2 — Versioning (when backend declares `versioning_native`)

```
14. GET    /files/{id}/versions                                  list versions
15. GET    /files/{id}/versions/{version_id}                     download specific version                                    — If-Match, If-None-Match, Range
16. HEAD   /files/{id}/versions/{version_id}                     version metadata headers                                     — If-Match, If-None-Match
17. DELETE /files/{id}/versions/{version_id}                     permanent version delete                                     — If-Match
```

## POST /files vs PATCH /files/{id}

| Aspect                       | `POST /files`                       | `PATCH /files/{id}`                                    |
|------------------------------|-------------------------------------|--------------------------------------------------------|
| Body                         | `multipart/form-data`               | `multipart/form-data`                                  |
| `metadata` part              | required (full metadata document)   | optional (JSON Merge Patch per RFC 7396)               |
| `content` part               | required (binary)                   | optional — **accepted only with `?replace_content=true`** (then replaces content); a `content` part without the flag is `400` |
| `?replace_content` query     | N/A                                 | `true` to opt into content replacement; default/absent = metadata-only. `true` with no `content` part is `400` |
| `If-Match`                   | N/A                                 | required                                               |
| Empty body / no parts        | `400`                               | `400`                                                  |
| State on success             | `available`                         | `available` (content replaced) / unchanged (metadata only) |

Content replacement is **full-file (`PUT`-style) semantics, not a partial patch**, and must be requested explicitly via the `?replace_content=true` query flag. With the flag set and a `content` part present, `PATCH` replaces the file content: `content_revision` is bumped, `metadata_revision` is bumped, `hash_value` is recomputed, and `ETag` changes. When the backing storage declares `versioning_native = true`, each content replacement creates a new version retrievable by version id; otherwise the prior content is permanently overwritten.

The flag exists to prevent **silent content mutation**: a client (generic proxy, form library forwarding stale state) that accidentally includes a `content` part would otherwise overwrite the file's bytes unnoticed — and `If-Match` does **not** catch this, since the current content ETag still matches at request time. Therefore a `content` part **without** `?replace_content=true` is rejected with `400`, and `?replace_content=true` **without** a `content` part is likewise `400` (the flag asserts an intent the body does not carry).

`PATCH` with a `metadata` part applies JSON Merge Patch semantics to `custom_metadata`: keys present in the patch overwrite their values, keys set to `null` delete the entry, keys absent from the patch are left untouched. Metadata-only updates bump `metadata_revision` and `Last-Modified` but do **not** change `ETag` or `hash_value` — both remain tied to the content.

## Conditional headers

- `If-Match`: required on every write (`PATCH`, `DELETE`) and on every multipart-control endpoint (`POST .../multipart/...`, `DELETE .../multipart/{upload_id}`). On read endpoints (`GET`, `HEAD`) it is optional; non-match returns `412 Precondition Failed`.
- `If-None-Match`: optional on `GET`/`HEAD`; match returns `304 Not Modified` with no body.
- ETag is opaque, deterministic per `(file_id, content_revision)`, and explicitly **not** equal to the content hash. The content hash is exposed as `X-FS-Hash-Algorithm` + `X-FS-Hash-Value` headers (P1: SHA-256 only, per ADR-0002).
- **ETag is content-only.** Metadata-only `PATCH` (no `content` part) does **not** change ETag — only `metadata_revision` and `Last-Modified` are bumped. Consequently `If-Match` on metadata-only `PATCH` protects against concurrent **content** writes but does **not** detect concurrent metadata writes.
- `If-Match-Metadata: <u64>`: **optional** on metadata-only `PATCH`; matched against the current `metadata_revision` (the value published on every response as `X-FS-Metadata-Revision`). Mismatch returns `412 Precondition Failed`. This gives lost-update protection for concurrent **metadata** writers, complementing content-only ETag. When the header is **absent**, metadata writes fall back to last-write-wins (back-compatible default); clients that keep meaningful state in custom metadata opt in. It is intentionally a separate header — not folded into ETag — so CDN caching of content is unaffected by metadata-only changes.

## Range support

- `GET /files/{id}` accepts `Range: bytes=<start>-<end>`, `bytes=<start>-`, and `bytes=-<suffix-length>`. A well-formed, satisfiable range returns `206 Partial Content` with `Content-Range: bytes <s>-<e>/<n>`. A well-formed but **unsatisfiable** range (e.g. `start ≥ size`) returns `416 Range Not Satisfiable` with `Content-Range: bytes */<n>`.
- A **syntactically invalid / unparseable** `Range` header (garbage value, unknown unit, malformed range-set) is **ignored** per RFC 7233 §3.1: the server responds `200 OK` with the full body, as if no `Range` had been sent. `416` is reserved exclusively for well-formed-but-unsatisfiable ranges.
- Every download response includes `Accept-Ranges: bytes`.
- `HEAD` ignores the `Range` header and always responds with full-file metadata; the `Accept-Ranges: bytes` header is still set to advertise support on `GET`.
- Multi-range requests (`bytes=0-99,200-299`) are parsed but **not** served as partial content in P1. Per RFC 7233 §4.1 the only conformant responses are the full representation (`200`) or a `multipart/byteranges` document; P1 returns **`200 OK` with the full body** (no `Content-Range`). A coalesced `206` spanning the union of the requested ranges is **not** RFC-conformant and is not used. `multipart/byteranges` may be added later as a backward-compatible upgrade.

## Response headers (download + HEAD)

```
ETag: "<opaque>"
Content-Type: <mime>
Content-Length: <bytes>             # full file on HEAD/200; range bytes on 206
Content-Range: bytes <s>-<e>/<n>    # only on 206
Accept-Ranges: bytes
Last-Modified: <RFC 7231 date>
X-FS-File-Id: <uuid>
X-FS-GTS-File-Type: gts.cf.fstorage.file.type.v1~...
X-FS-Hash-Algorithm: SHA-256                            # of content
X-FS-Hash-Value: <hex>                                  # of content
X-FS-Content-Revision: <u64>                            # increments only on content writes
X-FS-Metadata-Revision: <u64>                           # increments on any PATCH
X-FS-Version-Id: <opaque>                               # only on /versions/{version_id} responses (P2)
X-FS-Owner-Kind: user|app
X-FS-Owner-Id: <uuid>
X-FS-Created-At: <ISO 8601>
X-FS-Meta-<key>: <value>                                # one header per custom metadata key
```

## Status code summary

- `200 OK` — successful read or PATCH with state change.
- `201 Created` — successful `POST /files`.
- `204 No Content` — successful `DELETE`. The metadata row is removed before the best-effort backend object delete; re-`DELETE` of an already-deleted `file_id` returns `404` (idempotent).
- `206 Partial Content` — successful range read.
- `304 Not Modified` — `If-None-Match` matched current ETag.
- `400 Bad Request` — malformed request (missing required form parts, invalid JSON, etc.), or a `PATCH` whose content-replace intent and body disagree: a `content` part without `?replace_content=true`, or `?replace_content=true` with no `content` part.
- `403 Forbidden` — authorization denied.
- `404 Not Found` — file does not exist or version does not exist.
- `409 Conflict` — multipart state conflicts (e.g., complete on aborted upload).
- `412 Precondition Failed` — `If-Match` (content ETag) mismatch, or `If-Match-Metadata` mismatch against the current `metadata_revision`.
- `415 Unsupported Media Type` — declared mime does not match magic-bytes detection.
- `416 Range Not Satisfiable` — a well-formed `Range` that cannot be satisfied against the file size (e.g. `start ≥ size`). A syntactically invalid / unparseable `Range` is **not** a `416`: it is ignored and the full body is served with `200`.
- `422 Unprocessable Entity` — semantic validation failure (e.g., invalid GTS file type format).
- `507 Insufficient Storage` — backend or quota limit exceeded.
