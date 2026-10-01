# RPM spec for lion-greeter (Fedora / RHEL / SUSE families).
# rpmbuild -ba packaging/rpm/lion-greeter.spec

%bcond_without check

Name:           lion-greeter
Version:        0.6.0
Release:        1%{?dist}
Summary:        LionOS login daemon with conversation-forwarding PAM

License:        MIT
URL:            https://lionos.org/
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust-packaging >= 21
BuildRequires:  dbus-devel
BuildRequires:  pam-devel
Requires:       dbus
Requires:       pam
%{?systemd_requires}
BuildRequires:  systemd

%description
PAM authentication daemon for the LionOS login UI: live second-factor
prompt forwarding, configurable autologin, XDG session selection, and
logind-based fast user switching, all over a versioned, capability-
flagged D-Bus API restricted to the unprivileged lion-login account.

%prep
%autosetup -n %{name}-%{version}

%build
%cargo_build

%install
%cargo_install
install -Dpm 0644 lion-greeter.service %{buildroot}%{_unitdir}/lion-greeter.service
install -Dpm 0644 dbus-1/org.lionos.Greeter.conf \
    %{buildroot}%{_datadir}/dbus-1/system.d/org.lionos.Greeter.conf
install -Dpm 0644 pam.d/lion-greeter %{buildroot}%{_sysconfdir}/pam.d/lion-greeter
install -Dpm 0644 pam.d/lion-greeter-autologin \
    %{buildroot}%{_sysconfdir}/pam.d/lion-greeter-autologin
install -Dpm 0644 etc/lionos/greeter.toml.example \
    %{buildroot}%{_datadir}/lion-greeter/greeter.toml.example
install -d -m 0755 %{buildroot}%{_sharedstatedir}/lion-greeter

%check
%if %{with check}
%cargo_test
%endif

%post
%systemd_post lion-greeter.service

%preun
%systemd_preun lion-greeter.service

%postun
%systemd_postun_with_restart lion-greeter.service

%files
%license LICENSE*
%doc README.md CHANGELOG.md STABILITY.md SECURITY.md
%{_bindir}/lion-greeter
%{_unitdir}/lion-greeter.service
%{_datadir}/dbus-1/system.d/org.lionos.Greeter.conf
%{_datadir}/lion-greeter/greeter.toml.example
%{_sysconfdir}/pam.d/lion-greeter
%{_sysconfdir}/pam.d/lion-greeter-autologin
%dir %attr(0755,root,root) %{_sharedstatedir}/lion-greeter

%changelog
* Wed Sep 30 2026 LionOS Project <packaging@lionos.org> - 0.6.0-1
- 0.6.0: session selection, user switching, auth-method probing,
  lib/bin split, deterministic fuzz harness, distro packaging.
