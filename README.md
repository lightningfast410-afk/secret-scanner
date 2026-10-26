# Secret Scanner — find hardcoded secrets in configs and code

A small, standard-library-only scanner that walks a directory and
reports hardcoded secrets by file, line, and rule name. It never
prints a matched value — only `file:line:rule` and the value's
length — because a scanner that prints secrets is a second leak.

## Rules (7)

- `private-key` — private-key headers (`BEGIN ... PRIVATE KEY`)
- `aws-key` — AWS access-key shape
- `github-token` — GitHub token shapes (`ghp_`, `gho_`,
  `github_pat_`)
- `slack-token` — Slack token shape (`xox...`)
- `jwt` — JWT shape (three base64url segments)
- `generic-assignment` — a secret-named variable
  (`password`, `passwd`, `secret`, `api_key`, `token`) assigned
  a non-empty value, including bytes literals
- `env-assignment` — secret-named assignments in `.env`-style
  files

Text files only. Binary files, `__pycache__`, `.git`, and
`node_modules` are skipped. Placeholders, empty values, and
test dummy values are not flagged as production secrets.

## Usage

```
python3 secret_scanner.py <directory>
```

Exit codes: `0` = clean, `1` = findings, `2` = bad path
(not a directory, or the scanner binary cannot run).

## Proof (this package, re-run on the copies)

- `fixtures/dirty`: 6 findings, exit 1
  (`app.js` slack-token + generic-assignment,
  `config.env` aws-key + github-token + generic-assignment,
  `keys.pem` private-key)
- `fixtures/clean`: 0 findings, exit 0
- Bad path: exit 2
- Real run on a PHP gateway codebase: exactly 1 file flagged,
  no other file flagged

## Fixtures

`fixtures/dirty` holds planted, clearly-fake secrets used only
to prove detection. `fixtures/clean` holds placeholders, empty
values, and env-at-runtime code. No real credential appears
anywhere in this repo.

## Honest limit

Keyword-based rules cannot catch a secret assigned to a bare
variable name containing no secret keyword. The scanner reports
what it can see by shape and name; it does not prove a codebase
is secret-free. Pair it with code review and a secret store.

## License

No license file ships with this repo, so all rights reserved
by default.
