# Qolam Sentinel 0.16.0

## Responsible use notice for distributed copies

First GUI launch presents an English responsible-use notice before opening the workspace. The user must tick an initially unchecked acknowledgement to enable Continue. Exit or closing the dialog ends startup. The notice explains authorization, agreed scope, potential operational effects, data protection, user decisions and the creators' role.

It states that authorized public websites are supported and that the creators do not grant permission on behalf of target owners. Warranty and liability refer to the included GPL-3.0-only license and applicable law; the notice does not amend that license, promise legal immunity or declare unauthorized activity lawful. This is a product notice, not a jurisdiction-specific legal opinion.

Acknowledgement stays on the user's device in the application data folder. It contains notice version/hash, UTC timestamp and application version, with no name, target or signature. Changed or corrupt notice records trigger the popup again. If saving fails, the user sees a warning and may continue the acknowledged session; the popup returns next launch. It is an acknowledgement record, not proof of identity or target authorization.

The sidebar provides a read-only review of the notice. Target-specific scan authorization still applies. The sidebar's local-first wording is replaced with authorized-assessment wording so it does not suggest a localhost-only scanner. The release QA diagnostic remains separately restricted to loopback.

## Package and checks

RESPONSIBLE_USE.md is included in the portable package. No personal acknowledgement record is shipped. Tests cover version/hash records, malformed input, unchecked defaults, Continue gating, decline behavior, save warnings and startup exit before workspace initialization. See VERIFICATION_0.16.0.json for actual suite, packaged runtime and UI checks. Nothing is publicly uploaded or signed by this update.
