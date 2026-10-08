# Fix 01: SQL Injection in Product Search

| | |
|---|---|
| **Finding** | SAST-070, confirmed by DAST-006 |
| **File** | `routes/search.ts`, line 23 |
| **OWASP 2025** | A05 Injection |
| **CWE** | CWE-89 (SQL Injection) |

## The vulnerability

The search endpoint built its SQL query by inserting the user's search term
directly into the query string:

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

Because `criteria` comes straight from `req.query.q`, an attacker can break out
of the string and inject their own SQL. A UNION-based payload can read data from
other tables, including the Users table (emails and password hashes).

## The fix

Use a parameterized query. The user input is sent to the database as a bound
value, never as part of the SQL text:

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { criteria: `%${criteria}%` } }
)
```

The database now treats the input as a literal search string. The `%` wildcards
are part of the bound value, so legitimate searches are unaffected.

## How to verify

Before the fix, this returns a 500 error (the payload breaks the SQL):

    curl.exe -s "http://localhost:3000/rest/products/search?q=')) --"

After the fix, the same request returns a normal empty result set, and ordinary
searches (e.g. `?q=apple`) still work.