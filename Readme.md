# UPBGE BinaryCrypt

UPBGE BinaryCrypt encrypts the `.blend` files of a UPBGE game so that they can be shipped without
handing out the editable sources. It is the open-source successor of BPPlayer and follows the same
model: an **encryption tool** for the developer and a **launcher** shipped with the game.

| Component | Shipped with the game | Role |
|---|---|---|
| `bc_tool` | No | Editor and batch tool: encrypts the game files and writes the game executable. |
| `bc_launcher` | As the game executable | Template: `bc_tool` copies it under the game's name, with the manifest inside or next to it. Verifies the player, starts it and hands it the key. |
| UPBGE player (`blenderplayer`) | Yes, in `engine/` | Decrypts while loading. Built with `WITH_GAMEENGINE_BINARYCRYPT`. |

A shipped game looks like this: one executable, the encrypted data and the runtime folder.

```
MyGame.exe          game executable (launcher + manifest)
                    (binarycrypt.manifest next to it with the external manifest option)
game.blend          encrypted
levels/...          encrypted
engine/             UPBGE runtime: blenderplayer.exe, DLLs, <version>/python, <version>/datafiles
```

## What it protects, and what it does not

BinaryCrypt stops casual extraction: an encrypted file cannot be opened in Blender or UPBGE, the
decrypted data never touches the disk, the player refuses to save it back, and the launcher only
runs the exact player the game was encrypted for, by default with the exact libraries (`.dll`,
`.so`, `.dylib`, `.pyd`) of the game folder, and optionally its exact Python files. Any
modification of an encrypted file or of the manifest is detected.

The key necessarily exists on the player's machine while the game runs. A determined attacker with
a debugger can therefore recover it; no client-side scheme prevents that, and the source code being
public does not change it. Anti-debugging and code obfuscation are out of scope. Every game has its
own key by default, so a key recovered from one game opens no other; with an online key (below)
the key is in no shipped file at all: recovering it requires owning the game.

Only `.blend` files are encrypted. Pack textures, sounds and scripts into the `.blend` (Blender:
*File > External Data > Pack Resources*, Python scripts as Text blocks) to protect them too.
External `.py` modules imported by the game stay readable; the *+ Python* integrity level (below)
at least refuses them modified. Code injected into the running player (a debugger, an injector
tool, `LD_PRELOAD`) is out of reach of any file check.

## How it works

1. **Keys.** Every build of this repository generates a random 256-bit **build key** at build
   time and compiles it into `bc_tool` and `bc_launcher` only, stored as two shares so that
   neither executable holds it in one piece: each share sits at a random offset in 4 KiB of random
   bytes, one in read-only data and one in writable data. It never appears in the sources, the
   build flags or the build logs. The UPBGE player never contains it. The `.blend` files are encrypted with a
   **project key**, created for each game in a key file next to its project; the game executable
   carries it masked with the build key. A game can instead get its key from a key server at
   launch (*online key*), or use the build key itself (see *Keys*, below).
2. **Encryption.** `bc_tool` seals each `.blend` into a container of independent 64 KiB chunks,
   each authenticated with XChaCha20-Poly1305 ([Monocypher](https://monocypher.org)). Sealing is
   deterministic (the nonce derives from the key and the file's hash): an unchanged file gives the
   same bytes on every export, so store patches (Steam, Epic) only carry what changed, and an
   output that is already up to date is neither encrypted nor written again. It hashes the player
   executable and the other native code of the game folder (BLAKE2b) and writes the game
   executable: a copy of `bc_launcher` under the game's name with a manifest appended (player path
   and hash, native code digest, main file, the masked project key), authenticated with the build
   key.
3. **Launch.** The game executable reads and authenticates its manifest, hashes the player and
   the native code of the game folder, refuses to continue on any mismatch, starts the player on
   the main file and writes the key into an inherited pipe, then wipes its own copy. The key never
   travels on the command line or through a file. The player inherits that pipe and its standard
   streams only, not other handles of whoever started the game.
4. **Loading.** The player reads the key into a memory page locked out of swap (and, on Linux,
   out of core dumps), then decrypts containers chunk by chunk below Blender's file readers: the
   main file, `LibLoad`, linked libraries and zstd compressed files all work.

The container format and the launcher to player hand-off are specified in
[`common/binarycrypt_format.h`](common/binarycrypt_format.h). **This header exists as an identical
copy in UPBGE (`intern/binarycrypt/binarycrypt_format.h`); both copies must be kept in sync.**

## Building

Requirements: CMake 3.16 or newer and a C99 compiler. The editor uses
[raylib](https://www.raylib.com) 5.5 and [raygui](https://github.com/raysan5/raygui) 4.0
(vendored). When no installed raylib is found, raylib 5.5 is downloaded and built automatically.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release        # optional
```

Platform notes:

- **Windows:** a prebuilt raylib in `../Libs/raylib-5.5_win64_msvc16` is detected; otherwise it is
  downloaded. `bc_launcher.exe` is a GUI application: it never opens a console window.
- Keep `bc_launcher` next to `bc_tool`: the tool copies the launcher of its own build (same key)
  into each exported game.
- **Linux:** raylib needs the X11 and OpenGL development packages
  (`libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev libgl1-mesa-dev` on
  Debian/Ubuntu). File dialogs use `zenity` or `kdialog`; without them, drop files on the window
  or type the paths.
- **macOS:** file dialogs use the system `osascript`.

| CMake option | Default | Meaning |
|---|---|---|
| `BINARYCRYPT_BUILD_GUI` | `ON` | `OFF` builds a command-line-only `bc_tool` (no raylib), e.g. for CI. |
| `BINARYCRYPT_FETCH_RAYLIB` | `ON` | Download raylib 5.5 when it is not installed. |
| `BINARYCRYPT_KEY_FILE` | empty | Build with a fixed key instead of a random one (see below). |
| `BINARYCRYPT_HOST_KEYGEN` | empty | Host `bc_keygen` executable, required when cross compiling. |

## Key management

- **Project key file** (default *Key* mode): created on the first export, next to the project file
  and named after it (`mygame.bcproj` → `mygame.key`), or wherever *Key file* says. **Back it
  up**: every update of the published game must be encrypted with it. *Save as* under another
  name keeps using it. `bc_tool` refuses a key file inside the game folder.
- The **build key** changes **only on a clean build**. Reconfiguring, updating the sources or
  rebuilding keeps it. A project key game does not depend on it for its files: a game exported
  again with a newer BinaryCrypt keeps the bytes of every unchanged file, only the game executable
  changes (a small patch).
- `bc_tool` shows the build key **fingerprint** (toolbar, or `bc_tool --fingerprint`). A launcher
  only accepts manifests written by a `bc_tool` with the same fingerprint, i.e. from the same
  build: `bc_tool` copies the launcher of its own build into every game.
- With *Key: Build key*, patches or DLC for a released game need the same build key again. Either
  keep the `bc_tool` and `bc_launcher` binaries of that release, or save the key and pin it:

  ```bash
  bc_tool --export-key build.key                   # refuses to overwrite an existing file
  cmake -B build -DBINARYCRYPT_KEY_FILE=$PWD/build.key
  ```

- Never commit, share or ship a key file. Anyone holding a game's key file can decrypt that game;
  anyone holding your `bc_tool`, or a launcher of your build, can produce manifests that build's
  launchers accept, and unmask the project keys of its games (*Keys*, below). If you build in CI,
  keep the artifacts private.

## Encrypting a game

1. **Prepare the runtime.** Copy the UPBGE runtime (the player executable with everything next to
   it: DLLs, `blender.crt`, `blender.shared`, the `<version>` folder with `python` and `datafiles`)
   into `engine/` inside the folder you will ship. The player finds its files relative to its own
   location, so the whole runtime moves together. The player and the libraries of the game folder
   are hashed: export *after* placing the final runtime and any store library
   (`steam_api64.dll`, a key provider...), and export again whenever you change one.
2. **Describe the batch** in `bc_tool` (or write a `.bcproj` file, below):
   - *Source folder*: the root of your `.blend` tree.
   - *Output*: mirror into an output folder (recommended), or next to the sources.
   - *Game name*: name of the game executable (`.exe` is added on Windows). Empty: the main file
     name.
   - *Check* (default *+ Libraries*): see *Integrity check*, below.
   - *Manifest*: inside the game executable (default) or in a separate `binarycrypt.manifest`
     file next to it (see below).
   - *Icon*, *Version*, *Company*, *Copyright* (Windows, optional): see below.
   - *Key*: per project (default), online from a key server, or the build key; *Key file*: see
     *Keys*, below.
   - *Player*: the player inside the game folder; `engine/blenderplayer(.exe)` by default.
   - *Main file*: the `.blend` the game starts.
   - *Files to encrypt*: `.blend` files and folders (scanned recursively, hidden folders skipped).
     Drag and drop them on the window.
3. **Encrypt.** This writes the encrypted files and the game executable. Save the project to run
   the same batch again later, or from a script: `bc_tool --batch mygame.bcproj`.
4. **Sign** (optional, recommended on Windows): sign the game executable after exporting, e.g.
   `signtool sign ... MyGame.exe`. The manifest sits in front of the signature and stays readable.
   With the external manifest and no icon or version information, sign `bc_launcher` once
   instead: every export copies it byte for byte, so the signature stays valid. If you also sign
   the player, do it in step 1, before encrypting, because the player is hashed (with an icon or
   version information, see below).
5. **Ship** the game folder. Do not include `bc_tool`, the project file, a key file or the sources.

The game executable keeps working when renamed.

### Integrity check

The player loads more code than its executable: the DLLs and shared libraries next to it
(searched there first), Python extension modules, Python modules. Replacing one, or adding one
where the loader looks (a proxy `version.dll`, a `.pth` or `sitecustomize.py` in site-packages),
would run code inside the player with the keys in memory. *Check* (`integrity`) chooses what the
game executable verifies before every launch, against a digest the export stores in the manifest;
a file changed, added or removed since the export stops the game.

| Level | Checked | Cost at every launch (warm file cache, 2.3 GHz Xeon) |
|---|---|---|
| *Player* (`player`) | The player executable | Its hash only |
| *+ Libraries* (`native`, default) | And every `.exe`, `.dll`, `.so`, `.so.N`, `.dylib`, `.pyd` of the game folder, recursively | 300 MB of libraries in a folder of 10,000 files: 0.47 s, against 0.007 s with *Player* |
| *+ Python* (`python`) | And every `.py`, `.pyw`, `.pth`, `.zip` (the default `sys.path` names a `python3XX.zip` before the standard library) | 537 `.py` files (9.8 MB): +0.019 s. **And** the game recompiles every script it imports at every launch: about 0.15 s per MB of imported Python |

The game executable and the player have their own checks and are not part of the digest.

**Python bytecode at the *+ Python* level.** The player writes `.pyc` files next to the modules
it imports, so they cannot be part of a digest, and checking `.py` alone would be pointless: a
`.pyc` that claims its source's time and size is loaded without reading the source. So bytecode
is removed instead, everywhere in the game folder: by the export, before every launch and after
the player exits (a test run followed by an upload ships none). In a folder the player cannot
write (Program Files, `/opt`) none can appear, since the game shipped without any; one that
cannot be removed was put there by someone else, and the game refuses to start. The cost is the
loss of Python's bytecode cache: in a writable folder (a Steam library) the game compiles its
scripts at every launch, as it already does in a read-only one.

- Export again after adding a store library, updating the runtime or, at *+ Python*, changing a
  script.
- **Not covered at any level:** code injected into the running process, which needs no file, and
  a patched game executable.

### Manifest inside or next to the executable

| | Inside (default) | Separate file |
|---|---|---|
| Game folder | one executable | executable + `binarycrypt.manifest` |
| Code signing | sign every exported game executable | sign `bc_launcher` once, before exporting (unless the game has an icon or version information) |
| `strip`, UPX, macOS `codesign` on the exported executable | drop or reject the appended manifest: apply them to `bc_launcher` before exporting | harmless: the executable is a plain launcher |
| Games per folder | any | one (the file name is fixed, so renaming the executable keeps working) |

Both are equally protected: the manifest is authenticated with the key either way, so it can be
neither edited nor forged. The launcher looks inside itself first and only reads
`binarycrypt.manifest` when it carries no manifest; a damaged embedded manifest is an error, never
a reason to fall back to the file. Exporting with the manifest inside removes a stale
`binarycrypt.manifest` from the game folder.

### Icon and version information (Windows)

Setting any of *Icon*, *Version*, *Company* or *Copyright* brands both executables on every
export:

| | Game executable | Player (`engine/blenderplayer.exe`) |
|---|---|---|
| Icon | Explorer, desktop shortcuts | the game window: title bar, taskbar, Alt-Tab |
| Version information | file properties | file properties, the process name in Task Manager |

The product name and description are the game name; the version defaults to `1.0.0.0`. An `.ico`
with any set of sizes works (16 to 256 px). Only the `APPICON` icon group and the version resource
are replaced; the player's other resources (the `.blend` file icon, its manifest) stay as they are.
`bc_tool` brands the player before hashing it, so the game accepts it, and leaves an already
branded player untouched, byte for byte.

- **Signing:** branding rewrites both executables. Sign the player after the first export, then
  export again: it stays untouched, so the signature and the hash remain valid. Sign the game
  executable after exporting, in both manifest modes. `bc_tool` warns when branding invalidates a
  signature.
- Branding needs a Windows build of `bc_tool`, which is also what produces Windows games. Other
  builds ignore these settings with a warning.
- Emptying the settings does not restore the UPBGE icon: copy the runtime into `engine/` again.
- Explorer caches icons: a changed icon may take a while to show for the same file name.

### Keys

| | Per project (default) | Online | Build key |
|---|---|---|---|
| The files are encrypted with | the project key, from its key file | the project's keys, from its key file | the build key |
| The game executable gets it from | its manifest, unmasked with the build key | the key server, at each launch | itself (two shares) |
| Another game made with the same `bc_tool` | has another key | has another key | has the same key |
| Re-exported with a newer BinaryCrypt | unchanged files keep their bytes | unchanged files keep their bytes | every file changes (unless the build key is pinned) |
| Who can recover the key | anyone with a copy of the game who knows the scheme (public): the launcher holds the build key, in two hidden shares (a search over both blocks found it in 9 s on one core) | a player who owns the game, from the memory of a running copy | anyone with a copy of the game, and the key then opens every game of that build |

**What the per project key gives, and what it does not.** The key is masked with a value derived
from the build key, the key's id and the player's hash; no executable holds a key in one piece, so
scanning the game executable for one finds nothing (the tests check this). But the launcher has to
unmask it, and this repository says how: whoever extracts the build key from the launcher, or runs
the same `bc_tool` build (a prebuilt BinaryCrypt release is the same build for everyone who
downloads it), can unmask the key of any game of that build. What it does give, even with a shared
release: a key recovered from one game (from memory, or the pipe to the player) opens no other
game, and updating BinaryCrypt keeps store patches small. For a key that ships with no copy of the
game, use an online key; for a build key nobody else has, build BinaryCrypt yourself.

### Online key (Steam, Epic, your own server)

With *Key* set to *Online*, the `.blend` files are encrypted with a **content key** of the game,
as with a per project key, but no shipped file contains it, not even masked. At every launch the game
executable asks a **key provider** (a small program in the game folder, written for the store) to
prove to your **key server** that the player owns the game; the server answers with the content
key sealed for that launch only, which the game executable passes to the player as usual. The UPBGE
player is the same in both modes.

- *Key file*: the content key, created on the first export (by default next to the project file).
  It must not be inside the game folder (`bc_tool` refuses), goes on the key server, and must be
  **backed up**: every update of the game needs it.
- *Provider*: path inside the game folder, like the player. *URL*: the key server, given to the
  provider.
- *Always online*, or *Offline after 1st launch*: after one successful launch the key stays on the
  player's computer (Windows: protected with DPAPI for that Windows user; Linux and macOS: bound to
  the machine id and user, as hard to recover as the build key from the launcher).
- The game executable's command-line arguments go to the provider, never to the player: stores pass
  login tokens that way.

**Key per update** (optional, *Updates: New key per update*). By default one content key serves
the whole life of the game. With a key per update, each update you publish gets a new key: the
files that changed are encrypted with it, the unchanged files keep their earlier key and their
exact bytes, so patches stay small. A key leaked from one version does not open the files of later
updates: pirated copies stay behind at every update.

- Set the *Update number* (`key_update`) and raise it for each update you publish. Exports with the
  same number (while you work on it) reuse its key; the number cannot go back.
- The key file then holds one key per update plus a record of which key each file uses. After
  exporting a new update, **install the updated key file on the key server before publishing the
  update**, or its players get no key.
- The game executable asks for the keys its files use (at most 64, one per update that still has
  files in the game). With *Offline after 1st launch*, only the new update's key is fetched.
- Switching back to *One key* encrypts every file with the newest key (a full patch once).

The provider runs as a separate process so it can link a store's proprietary SDK, which a GPL
program cannot. Reference providers for Steam and Epic, a development provider, the key server and
the protocol are in [`keyserver/`](keyserver/README.md), under the MIT license.

### Output modes

- **Mirror** (recommended): the output folder receives an encrypted copy of the source tree with
  the **same names**, so relative paths (`//levels/a.blend`), linked libraries, `LibLoad` and
  `bge.logic.getBlendFileList()` keep working unchanged. The output folder is the game folder.
- **Next to the sources**: each `name.blend` gets an encrypted `name.upbgebc` beside it, and the
  source folder is the game folder. Linked libraries still point to `.blend` names and
  `getBlendFileList()` only lists `.blend` files, so this mode suits single-file games, or games
  that load their other files explicitly by their `.upbgebc` names.

Re-encrypting replaces outputs atomically: an interrupted batch never leaves a partial file. An
output whose size and header already match what sealing would write (same key, same content) is
kept as it is: re-exporting an unchanged 257 MB game took 0.38 s instead of 1.5 s. Only its header
is compared, so damage further in is not repaired by an export (the player still refuses it). When
a folder scan finds an already encrypted `.blend` (an old output), it is skipped with a warning.

### Project file (`.bcproj`)

Plain text, one `key = value` per line. `#` starts a comment at the beginning of a line or after
a space or a tab; double quotes keep it, and leading or trailing spaces, in a value. Paths are
relative to the project file. Unknown keys are errors.

```ini
version = 1
source_root = src
output_mode = mirror            # mirror | inplace
output_dir = dist               # mirror only
game_name = MyGame              # optional, default: main file name
manifest = embedded             # embedded | external (binarycrypt.manifest); default embedded
icon = art/game.ico             # Windows, optional: icon of the game executable and window
game_version = 1.2.0            # Windows, optional: version information (default 1.0.0.0)
company = My Studio             # Windows, optional
copyright = "(c) 2026 My Studio"  # Windows, optional
key = online                    # project (default) | online | build
key_file = keys/mygame.key      # project, online: created on the first export; default
                                #   <project name>.key next to the project file
key_provider = engine/bc_provider_steam.exe  # online: relative to the game folder
key_url = https://keys.example.com/key       # online: given to the provider
key_cache = none                # online: none | permanent (offline after the first launch)
key_rotation = off              # online: off (one key) | per_update (a new key per update)
key_update = 1                  # online, per_update: number of the update being exported
integrity = native              # player | native (default, + libraries) | python (+ Python files)
player = engine/blenderplayer.exe   # relative to the game folder
main = src/game.blend
input = src                     # a folder (scanned for *.blend) or a file; repeatable
```

## Game executable messages

| Message | Cause |
|---|---|
| *the game was encrypted by a different tool build than this launcher* | Key mismatch: the `bc_launcher` copied into the game came from another build than the `bc_tool` that encrypted it. |
| *the player ... has been modified or replaced* | The player differs from the one hashed at encryption time. Encrypt again after updating it. |
| *the game manifest has been modified* / *the game manifest is corrupt* | The manifest (inside the executable, or `binarycrypt.manifest`) was edited or damaged. Encrypt again. |
| *this executable carries no game and there is no binarycrypt.manifest next to it* | `bc_launcher` started directly, data was appended after the embedded manifest, or the manifest file was not shipped. Export with `bc_tool`. |
| *... is missing* | The player or the main file is not where the manifest says. |
| *a library or program (or Python file) of the game folder was changed, added or removed* | Integrity check: a file it covers differs from the export. Export again after changing the runtime or a script. |
| *... cannot be removed (Python bytecode that was not part of the game ...)* | *+ Python* level: a `.pyc` in a folder the player cannot write. The game shipped without any; reinstall it. |
| *cannot reach the key server*, *access denied*, ... | Online key: the provider's or key server's own message. |
| *the key provider did not answer within 60 seconds* | Online key: the provider hung (store client not running?). |
| *the key server sent the key of another game* | Online key: the key server's configuration maps this game to the wrong key file. |

Command-line arguments given to the game executable never reach the player (online key games
forward them to the provider). The protected player also ignores `-p`.

## Repository layout

```
common/      core shared by the tool and the launcher (format, sealing, manifest, game executable, Windows branding, project, batch)
keygen/      build-time key generator
launcher/    bc_launcher
tool/        bc_tool: command line, editor (raylib + raygui), native file dialogs
tests/       unit tests and an end-to-end test (tool -> launcher -> stand-in player)
keyserver/   online keys: reference key server and providers (MIT)
```

## License

GPL-3.0 (see `LICENSE.txt`). The source files are GPL-2.0-or-later, as UPBGE, except `keyserver/`
(MIT, see `keyserver/LICENSE`). Monocypher is BSD-2-Clause or CC0-1.0; raygui is zlib/libpng.

**Your game's license.** BinaryCrypt does not change what the GPL asks of a game. The Blender
Foundation considers `.blend` files program output, owned by their author, but Python scripts that
use Blender's API, when distributed, GPL licensed ([Blender FAQ](https://www.blender.org/support/faq/)).
Game logic scripts inside an encrypted `.blend` may therefore have to be made available as source
on request. This is not legal advice: ask a lawyer for your case.
