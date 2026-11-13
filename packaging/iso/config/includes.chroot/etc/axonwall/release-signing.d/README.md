# Release-signing keyring (`/etc/axonwall/release-signing.d/`)

`axonwall-update` verifies a downloaded release checksum against **any**
public key in this keyring: the legacy single anchor
`/etc/axonwall/release-signing.pub` plus every `*.pub` file in this
directory. Only `*.pub` (public) keys belong here — never a private key.

## Why a keyring (E-M2, round-3 bug hunt)

The updater used to trust exactly one public key, and the new anchor
shipped only inside the `.deb` — which the old key cannot verify. A
release signed with a new key therefore failed verification on every
deployed box, so the release carrying the new anchor could never be
downloaded: rotation bricked updates fleet-wide until the pubkey was
replaced out of band on every box. The keyring breaks the cycle: a
transition release signed by the OLD key delivers the NEW anchor, and
the following release can be signed by the new key.

## Rotation procedure (operator steps)

1. Generate the new keypair offline. Keep the private key with the
   release-signing secret; Josh holds the only private-key copy.
2. Add the new public key to this directory in the repo as
   `<descriptive-name>.pub` (for example `release-signing-2027.pub`).
   It ships in the Debian ISO chroot, in the `.deb`
   (`packaging/debian/build-deb.sh`), and into staged slots via
   `sync_static_etc_axonwall` in `axonwall-update` — and, from the
   E-M3 fix, in the Alpine overlay as well.
3. Cut a **transition release** signed with the OLD key (the release
   workflow signs with `AXONWALL_RELEASE_SIGNING_KEY` as today). Every
   box that installs it gains the new anchor in its keyring.
4. Once the fleet has the transition release, rotate the
   `AXONWALL_RELEASE_SIGNING_KEY` repo secret to the NEW private key
   and sign subsequent releases with it. Boxes verify against the new
   anchor already in their keyring.
5. Retire the old anchor only after the fleet is past the transition
   release: delete the old `.pub` from this directory (and, for
   already-deployed boxes, from `/etc/axonwall/release-signing.pub`
   or the keyring) in a later release. Until then, keeping both anchors
   is what makes the transition work — an old anchor in the ring does
   not weaken verification, since a signature must still match one of
   the listed keys.

## What NOT to do

- Do not put a private key in this directory, in the repo, or in any
  image. The private key lives only in the `AXONWALL_RELEASE_SIGNING_KEY`
  repo secret (and Josh's offline copy).
- Do not dual-sign a transition release: it is unnecessary. The old-key
  signature on the transition release is what authenticates the new
  anchor's delivery.
- Do not remove the old anchor before the fleet has installed a release
  that carries the new one — that is the brick-the-fleet step the
  keyring exists to avoid.
