"""Lightweight SQL statement classification.

This is deliberately conservative: it only needs to tell reads from writes and
find which tables a destructive statement touches. Anything it can't
understand is reported as ``sql.other`` so the policy can still ask.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_IDENT = r'(?:"[^"]+"|[A-Za-z_][\w$]*)(?:\s*\.\s*(?:"[^"]+"|[A-Za-z_][\w$]*))?'


@dataclass
class Statement:
    category: str            # sql.read, sql.drop, sql.delete, ...
    text: str
    tables: list[str] = field(default_factory=list)
    where: str | None = None  # WHERE clause for DELETE/UPDATE, used to estimate impact


def split_statements(sql: str) -> list[str]:
    """Split on semicolons outside quotes, comments and dollar-quoted bodies."""
    out, buf, i, n = [], [], 0, len(sql)
    quote: str | None = None
    while i < n:
        ch = sql[i]
        if quote:
            if quote.startswith("$"):
                if sql.startswith(quote, i):
                    buf.append(quote)
                    i += len(quote)
                    quote = None
                    continue
            elif ch == quote:
                if i + 1 < n and sql[i + 1] == quote:  # escaped '' or ""
                    buf.append(ch * 2)
                    i += 2
                    continue
                quote = None
            buf.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "$":
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                quote = m.group(0)
                buf.append(quote)
                i += len(quote)
                continue
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    stmt = "".join(buf).strip()
    if stmt:
        out.append(stmt)
    return out


def _clean(name: str) -> str:
    return re.sub(r"\s+", "", name)


def _table_list(s: str) -> list[str]:
    return [_clean(m.group(0)) for m in re.finditer(_IDENT, s)]


def classify_statement(stmt: str) -> Statement:
    s = stmt.strip()
    u = s.upper()
    first = u.split(None, 1)[0] if u else ""

    if first in ("SELECT", "SHOW", "EXPLAIN", "VALUES", "TABLE", "DESCRIBE", "DESC") or s.startswith("\\"):
        if first == "EXPLAIN" and re.search(r"\bANALYZE\b", u) and re.search(r"\b(DELETE|UPDATE|INSERT|DROP)\b", u):
            return Statement("sql.other", s)
        return Statement("sql.read", s)
    if first == "WITH":
        if re.search(r"\b(DELETE|UPDATE|INSERT|MERGE)\b", u):
            return Statement("sql.other", s)
        return Statement("sql.read", s)

    m = re.match(r"DROP\s+(DATABASE|SCHEMA)\b", u)
    if m:
        return Statement("sql.drop_database", s)
    m = re.match(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(.+?)(?:\s+(?:CASCADE|RESTRICT))?\s*$", s, re.I | re.S)
    if m:
        return Statement("sql.drop", s, _table_list(m.group(1)))
    if first == "DROP":
        return Statement("sql.drop_other", s)

    m = re.match(r"TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(.+?)(?:\s+(?:RESTART|CONTINUE)\s+IDENTITY)?(?:\s+(?:CASCADE|RESTRICT))?\s*$",
                 s, re.I | re.S)
    if m:
        return Statement("sql.truncate", s, _table_list(m.group(1)))

    m = re.match(rf"DELETE\s+FROM\s+(?:ONLY\s+)?({_IDENT})(?:\s+(?:AS\s+)?(?!WHERE\b|USING\b|RETURNING\b)\w+)?(.*)$", s, re.I | re.S)
    if m:
        rest = m.group(2)
        w = re.search(r"\bWHERE\b(.*)$", rest, re.I | re.S)
        simple = not re.search(r"\b(USING|RETURNING)\b", rest, re.I)
        return Statement("sql.delete", s, [_clean(m.group(1))], w.group(1).strip() if (w and simple) else None)

    m = re.match(rf"UPDATE\s+(?:ONLY\s+)?({_IDENT})(?:\s+(?:AS\s+)?(?!SET\b)\w+)?\s+SET\b(.*)$", s, re.I | re.S)
    if m:
        rest = m.group(2)
        w = re.search(r"\bWHERE\b(.*)$", rest, re.I | re.S)
        simple = not re.search(r"\b(FROM|RETURNING)\b", rest[: w.start()] if w else rest, re.I)
        return Statement("sql.update", s, [_clean(m.group(1))], w.group(1).strip() if (w and simple) else None)

    m = re.match(rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({_IDENT})", s, re.I)
    if m:
        return Statement("sql.alter", s, [_clean(m.group(1))])

    if first in ("INSERT", "COPY", "MERGE"):
        return Statement("sql.write", s)
    if first in ("CREATE", "COMMENT", "GRANT", "REVOKE", "REINDEX", "VACUUM", "ANALYZE", "CLUSTER", "REFRESH"):
        return Statement("sql.write", s)
    if first in ("BEGIN", "COMMIT", "ROLLBACK", "SET", "RESET", "START", "END", "SAVEPOINT", "RELEASE"):
        return Statement("sql.read", s)
    return Statement("sql.other", s)


def classify_sql(sql: str) -> list[Statement]:
    return [classify_statement(s) for s in split_statements(sql)]
