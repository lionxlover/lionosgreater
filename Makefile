# lion-greeter Makefile — the one entry point for build / test / install.
#
# Goals:
#   make            build (debug)
#   make release    optimized build
#   make test       unit + integration + fuzz harness + live D-Bus suite
#   make check      fmt + clippy (the same gates CI runs)
#   make install    install into DESTDIR (or / by default, as root)
#   make uninstall  remove what install put down
#   make dist       source tarball for distro packaging
#   make clean      target dir
#
# Intended users: distro packagers (who want the raw cargo commands),
# sysadmins on a recovery shell, and CI (which literally runs
# `make check test`).

DESTDIR ?=
PREFIX  ?= /usr
BINDIR  := $(PREFIX)/bin
UNITDIR := $(PREFIX)/lib/systemd/system
DBUSDIR := $(PREFIX)/share/dbus-1/system.d
DOCDIR  := $(PREFIX)/share/doc/lion-greeter
SYSCONF := /etc
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

.PHONY: default release test check live install uninstall dist clean

default:
	cargo build --locked

release:
	cargo build --locked --release

test:
	cargo test --locked --all-targets

# The full local gate: everything CI runs except cargo-audit.
check:
	cargo fmt --all -- --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --locked --all-targets

live: release
	bash scripts/live_dbus_test.sh

install: release
	install -Dm755 target/release/lion-greeter $(DESTDIR)$(BINDIR)/lion-greeter
	install -Dm644 lion-greeter.service $(DESTDIR)$(UNITDIR)/lion-greeter.service
	install -Dm644 dbus-1/org.lionos.Greeter.conf $(DESTDIR)$(DBUSDIR)/org.lionos.Greeter.conf
	install -Dm644 pam.d/lion-greeter $(DESTDIR)$(SYSCONF)/pam.d/lion-greeter
	install -Dm644 pam.d/lion-greeter-autologin $(DESTDIR)$(SYSCONF)/pam.d/lion-greeter-autologin
	install -Dm644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -Dm644 CHANGELOG.md $(DESTDIR)$(DOCDIR)/CHANGELOG.md
	install -Dm644 STABILITY.md $(DESTDIR)$(DOCDIR)/STABILITY.md
	install -Dm644 SECURITY.md $(DESTDIR)$(DOCDIR)/SECURITY.md
	# Example config lands in share/, never clobbering /etc.
	install -Dm644 etc/lionos/greeter.toml.example $(DESTDIR)$(PREFIX)/share/lion-greeter/greeter.toml.example
	install -d -m755 $(DESTDIR)/var/lib/lion-greeter
	@echo "installed lion-greeter $(VERSION) -> DESTDIR=$(DESTDIR)"
	@echo "enable with: systemctl enable --now lion-greeter.service"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lion-greeter \
	      $(DESTDIR)$(UNITDIR)/lion-greeter.service \
	      $(DESTDIR)$(DBUSDIR)/org.lionos.Greeter.conf \
	      $(DESTDIR)$(SYSCONF)/pam.d/lion-greeter \
	      $(DESTDIR)$(SYSCONF)/pam.d/lion-greeter-autologin \
	      $(DESTDIR)$(PREFIX)/share/lion-greeter/greeter.toml.example
	rm -rf $(DESTDIR)$(DOCDIR)
	# State and live config are intentionally kept: they belong to
	# the machine's operator, not the package.

dist:
	git archive --format=tar.gz --prefix=lion-greeter-$(VERSION)/ \
		-o lion-greeter-$(VERSION).tar.gz HEAD
	@echo "lion-greeter-$(VERSION).tar.gz (from git; use the Makefile in it)"

clean:
	cargo clean
	rm -f lion-greeter-$(VERSION).tar.gz
