# lion-greeter distro packaging

Three in-repo packaging specs, maintained next to the source they
package (drift between them is a bug):

| Family | File | Build command |
|---|---|---|
| Arch / pacman / AUR | `PKGBUILD` | `makepkg -si` |
| Debian / Ubuntu | `debian/` | `dpkg-buildpackage -us -uc` (or `debuild`) |
| Fedora / RHEL / SUSE | `rpm/lion-greeter.spec` | `rpmbuild -ba rpm/lion-greeter.spec` |

All three:

* build from the same `--locked` crate graph as CI,
* run the full test suite at package-build time (`check`),
* install the same file set: the binary, the systemd unit, the D-Bus
  system policy, both PAM stacks, an example `greeter.toml`, the
  `/var/lib/lion-greeter` state directory, and the operator docs
  (README / CHANGELOG / STABILITY / SECURITY).

The example config installs under `/usr/share/lion-greeter/`, not
`/etc` — the daemon treats a missing `/etc/lionos/greeter.toml` as the
normal first-boot state (defaults, autologin off), and `dpkg`/`rpm`
never clobber a sysadmin's live config on upgrade. Install scripts
that want a starter config should copy the example once.

For the systemd unit's hardening directives see `lion-greeter.service`
in the repository root — the unit is identical in all three packages.
