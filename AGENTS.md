# security extension — notes for agents

The full reference (settings keys, constants, CLI, Site Health tests, stored data, gotchas) is the AI Dev
Kit doc `docs/extensions/security.md`. Read it before editing. The rules below are the ones that break
something when forgotten.

- **Off means no hooks.** A module registers its hooks only when its switch is on and
  `UPW_SECURITY_SAFE_MODE` is not set. Keep it that way: it is what makes each switch its own rollback.
- **Never persist state outside the extension's options, transients and user meta.** No rewrite rules,
  no files, no `wp-config.php` / `.htaccess` writes. Deactivation must return WordPress to stock at once.
- **Classes go in `lib/`, not `includes/`** — the extension loader plain-includes `includes/*.php`, which
  redeclares anything the main class already required (fatal on activation).
- **Read settings raw in `_init()`** (`get_settings()`), never through `fw_get_db_ext_settings_option()`
  there: that initialises option types before other extensions register theirs.
- **Every behaviour-changing measure needs a way back that does not need the admin screen:** a constant
  (or safe mode) and a `wp upw-security …` command. Add both with any new measure.
- **Option descriptions state what the measure does not do.** Keep that when editing copy.
- **After a change:** `wp eval-file tests/security-contracts-test.php` (exit 0), then test in a browser
  on `localhost/testsite` — including the lockout and its recovery. Never test lockouts on `localhost/`.
