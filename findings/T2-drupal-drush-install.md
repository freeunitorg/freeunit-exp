# T2 — Drupal 12 install without drush: verified against Drupal core

Pinned: `drupal/drupal` @ `12.0.0-beta1`, compared against `11.4.8`. Only the four quotes the task
asked for; the drush/guzzle resolution question is out of scope and is stated as such at the end.

Files were read at those exact tags, not from a branch.

## (a) The `install` command has no `--db-url`, and SQLite is hardcoded

`core/lib/Drupal/Core/Command/InstallCommand.php:53-66` declares three options and one argument —
`install-profile-or-recipe` (`:57`), `langcode` (`:58`), `password` (`:59`), `site-name` (`:60`).
No database URL option exists in the class.

`core/lib/Drupal/Core/Command/InstallCommand.php:174-190` then supplies the form values itself:

```php
  protected function install($class_loader, SymfonyStyle $io, $profile, $langcode, $site_path, $site_name, string $recipe, #[\SensitiveParameter] ?string $password = NULL) {
    $sqliteDriverNamespace = 'Drupal\sqlite\Driver\Database\sqlite';
    ...
      'forms' => [
        'install_settings_form' => [
          'driver' => $sqliteDriverNamespace,
          $sqliteDriverNamespace => [
            'database' => $site_path . '/files/.sqlite',
          ],
        ],
```

and `execute()` refuses to start without the extension:
`if (!extension_loaded('pdo_sqlite'))` → `error('You must have the pdo_sqlite PHP extension
installed. ...')` (`:73-75`).

## (b) A valid `settings.php` with a non-empty `hash_salt` skips the database form

`core/includes/install.core.inc:396-398`:

```php
  // A valid settings.php has database settings and a hash_salt value. Other
  // settings will be checked by \Drupal\system\Install\SystemRequirements.
  $install_state['settings_verified'] = $install_state['config_verified'] && $install_state['database_verified'] && (bool) Settings::get('hash_salt', FALSE);
```

and the task that would otherwise ask for database credentials is skipped on it —
`core/includes/install.core.inc:777-785`:

```php
    'install_settings_form' => [
      'display_name' => t('Set up database'),
      'type' => 'form',
      // Even though the form only allows the user to enter database settings,
      // we still need to display it if settings.php is invalid in any way,
      // since the form submit handler is where settings.php is rewritten.
      'run' => $install_state['settings_verified'] ? INSTALL_TASK_SKIP : INSTALL_TASK_RUN_IF_NOT_COMPLETED,
      'function' => 'Drupal\Core\Installer\Form\SiteSettingsForm',
    ],
```

So the mechanism in the claim is exact: `hash_salt` is one of the three conditions, and the settings
form — the SQLite path — is `INSTALL_TASK_SKIP` once it holds. `install.core.inc:2100-2102` confirms
the same flag routes away from writing the default settings files.

## (c) Core's own CLI is `vendor/bin/dr`

`core/composer.json:126-128`:

```json
    "bin": [
        "scripts/dr"
    ],
```

## (d) `#[AsCommand]` discovery exists

`core/lib/Drupal/Core/DependencyInjection/Compiler/ConsoleCompilerPass.php:7` imports
`Symfony\Component\Console\Attribute\AsCommand`; `process()` walks the namespaces the container
knows (`:24-26`) and yields a class as a command when the attribute is present (`:101-103`):

```php
          if (count($reflectionClass->getAttributes(AsCommand::class)) > 0) {
            yield $class;
          }
```

That is the discovery the claim relies on for putting post-install operations in an enabled
module's command.

## Does the same hold for 11.4.8? Yes

Each anchor was extracted from both tags and compared line by line — byte-identical. Only the line
numbers move, and only in two files:

| anchor | 12.0.0-beta1 | 11.4.8 |
|---|---|---|
| `configure()` / `addOption('langcode'` | 53 / 58 | 53 / 58 |
| SQLite driver namespace / `.sqlite` database | 175 / 188 | 175 / 188 |
| `settings_verified =` expression | 398 | 397 |
| `install_settings_form` `run =>` / `function =>` | 783 / 784 | 777 / 778 |
| `"bin": ["scripts/dr"]` | 126-127 | 133-134 |
| `getAttributes(AsCommand::class)` | 101 | 101 |

The full file diff between the two tags touches none of the quoted lines.

## Not checked here

The drush-side half of the claim — `drush/drush:^13` requiring `guzzlehttp/guzzle ^7`, the 12.0 lock
pinning guzzle 8, and packagist refusing the 7.x releases — is a Composer/packagist resolution
question, not a core-source one, so it is outside the four quotes this task asked for. Nothing above
depends on it: (a)-(d) hold for core alone.

## Verification log

- each file fetched at the tag itself and every anchor located by content, then both tags compared
  mechanically; the comparison is what produced the table above;
- no claim carried over from a summary: the quotes were re-read at `12.0.0-beta1` before the pull
  request body was written.
