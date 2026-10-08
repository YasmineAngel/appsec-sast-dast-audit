# Fix 03: SQL Injection in Login

| | |
|---|---|
| **Finding** | SAST-063 |
| **File** | `routes/login.ts`, line 34 |
| **OWASP 2025** | A05 Injection |
| **CWE** | CWE-89 (SQL Injection) |

## The vulnerability

The login query inserted the submitted email directly into the SQL string:

```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

Submitting the email `' OR 1=1--` turns the condition always true and comments
out the password check:

```sql
SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = '...'
```

The query returns the first user (the administrator), logging the attacker in as
admin with no valid password. This is authentication bypass via SQL injection.

## The fix

Parameterize both values. The email and password hash are sent as bound
replacements, never as part of the SQL text:

```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL`,
  {
    replacements: {
      email: req.body.email || '',
      password: security.hash(req.body.password || '')
    },
    model: UserModel,
    plain: true
  }
)
```

`' OR 1=1--` is now treated as a literal email address. No user matches it, so
the login fails as expected.

## How to verify

Before the fix, this returns an authentication token (logged in as admin):

    curl.exe -s -X POST "http://localhost:3000/rest/user/login" -H "Content-Type: application/json" -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"

After the fix, the same request returns HTTP 401 Invalid email or password,
while a valid login still succeeds.