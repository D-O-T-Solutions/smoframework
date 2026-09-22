Name:           smo
Version:        0.0.5
Release:        1%{?dist}
Summary:        Secure Mesh Operation runtime

License:        MIT
URL:            https://github.com/smo-framework/smo
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cmake >= 3.20
BuildRequires:  gcc-c++ >= 11
BuildRequires:  ninja-build
BuildRequires:  openssl-devel >= 3.0
BuildRequires:  fmt-devel
BuildRequires:  spdlog-devel
BuildRequires:  simdjson-devel
BuildRequires:  liboqs-devel >= 0.9.0
%if 0%{?fedora} >= 39 || 0%{?rhel} >= 9
BuildRequires:  pkgconfig(yaml-cpp)
%else
BuildRequires:  yaml-cpp-devel
%endif

Requires:       glibc >= 2.35
Requires:       openssl-libs >= 3.0
Requires:       systemd
Requires:       liboqs >= 0.9.0
Suggests:       docker, docker-compose, openvpn

%description
SMO (Secure Mesh Operation) is a capability-scoped distributed execution runtime
for building secure, decentralized mesh networks. This package provides the
smo-node daemon and CLI tools for managing mesh nodes.

%prep
%autosetup -p1

%build
mkdir -p build
cd build
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=%{_prefix} \
    -DWITH_PQC=ON \
    ..
ninja

%install
rm -rf %{buildroot}
cd build
DESTDIR=%{buildroot} ninja install

# Install systemd service
install -Dpm 0644 ../scripts/smo-node.service %{buildroot}%{_unitdir}/smo-node.service

# Create config and data directories
install -dm 0755 %{buildroot}%{_sysconfdir}/smo
install -dm 0755 %{buildroot}%{_localstatedir}/lib/smo
install -dm 0755 %{buildroot}%{_localstatedir}/lib/smo-mesh

# Remove development files (headers, static libraries, cmake configs)
rm -rf %{buildroot}%{_includedir}
rm -rf %{buildroot}%{_libdir}/cmake
rm -f %{buildroot}%{_libdir}/*.a
rm -f %{buildroot}%{_libdir}/pkgconfig/*.pc

%pre
getent group smo >/dev/null || groupadd -r smo
getent passwd smo >/dev/null || useradd -r -g smo -d %{_localstatedir}/lib/smo -s /sbin/nologin -c "SMO Mesh Node" smo

%post
systemctl daemon-reload >/dev/null 2>&1 || :
# Enable but don't start by default
systemctl enable smo-node.service >/dev/null 2>&1 || :

%preun
if [ $1 -eq 0 ]; then
    systemctl stop smo-node.service >/dev/null 2>&1 || :
    systemctl disable smo-node.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ]; then
    systemctl try-restart smo-node.service >/dev/null 2>&1 || :
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/smo-node
%{_bindir}/smo-cli
%{_bindir}/smo
%{_bindir}/smo-admin
%{_bindir}/smo-debug
%{_unitdir}/smo-node.service
%dir %{_sysconfdir}/smo
%dir %{_localstatedir}/lib/smo
%dir %{_localstatedir}/lib/smo-mesh

%changelog
* Sun Sep 22 2024 SMO Team <smo@example.com> - 0.0.5-1
- Initial RPM release for v0.0.5
- smo-node daemon with systemd integration
- CLI tools: smo, smo-cli, smo-admin, smo-debug
- Post-quantum crypto support (ML-DSA, ML-KEM via liboqs)
- Observability: Prometheus metrics, OpenTelemetry tracing