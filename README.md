# security-toolkit

A small Python toolkit with the basic building blocks of application security, using only the standard library.

## Modules

- **`seckit.password`**: password strength assessment (entropy estimate, common-password list, keyboard/alphabet sequences, repeated characters) and a cryptographically secure generator (`secrets`) that always includes every selected character class.
- **`seckit.hashing`**: salted password hashing with PBKDF2-HMAC-SHA256 (600,000 iterations), constant-time verification with `hmac.compare_digest`, and streaming file checksums to verify integrity.
- **`seckit.cli`**: command line front-end.

## Stack

Python 3.11+ · standard library · pytest

## Usage

```bash
python -m seckit.cli check 'MyPassw0rd!'
python -m seckit.cli generate --length 20
python -m seckit.cli hash 'secret'                       # prints pbkdf2_sha256$iterations$salt$hash
python -m seckit.cli verify 'secret' '<stored hash>'     # exit code 0 on match
python -m seckit.cli checksum some-file.iso --algo sha256
pytest
```

## Security notes

- Random salt per hash, so equal passwords give different hashes.
- The entropy estimate is an upper bound (`length * log2(charset)`) and is penalised for patterns. It is a teaching aid, not a replacement for a full estimator like zxcvbn.
- Passwords passed as CLI arguments can end up in shell history. This is a learning project: in real systems read secrets from a prompt or stdin.
