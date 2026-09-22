# CPack RPM Generator Configuration for SMO Framework
# Reuses DEB config where possible, adds RPM-specific settings

# ── Package metadata (shared with DEB) ────────────────────────────────
set(CPACK_RPM_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
set(CPACK_RPM_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION}")
set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_SUMMARY "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_VENDOR "${CPACK_PACKAGE_VENDOR}")
set(CPACK_RPM_PACKAGE_URL "${CPACK_PACKAGE_HOMEPAGE_URL}")

# ── File naming ────────────────────────────────────────────────────────
set(CPACK_RPM_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

# ── Dependencies (Fedora/RHEL equivalents of DEB deps) ────────────────
# libc6 >= 2.35 -> glibc >= 2.35 (Fedora 39+ has 2.38+)
# openssl3 -> openssl-libs
# systemd -> systemd
# Add crypto deps for liboqs if PQC enabled
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.35, openssl-libs >= 3.0, systemd")
if(WITH_PQC)
    set(CPACK_RPM_PACKAGE_REQUIRES "${CPACK_RPM_PACKAGE_REQUIRES}, liboqs >= 0.9.0")
endif()

# Suggests (optional deps)
set(CPACK_RPM_PACKAGE_SUGGESTS "docker, docker-compose, openvpn")

# ── Architecture ───────────────────────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(CPACK_RPM_PACKAGE_ARCHITECTURE "aarch64")
else()
    set(CPACK_RPM_PACKAGE_ARCHITECTURE "${CMAKE_SYSTEM_PROCESSOR}")
endif()

# ── Build root and spec file ───────────────────────────────────────────
set(CPACK_RPM_BUILDROOT "%{_tmppath}/%{name}-%{version}-%{release}-buildroot")
set(CPACK_RPM_SPEC_FILE "${CMAKE_SOURCE_DIR}/packaging/rpm/smo.spec")
set(CPACK_RPM_SPEC_INSTALL_POST "/usr/lib/rpm/brp-compress || true")

# ── Maintainer/scripts ─────────────────────────────────────────────────
set(CPACK_RPM_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")

# ── Changelog (auto-generated from git) ────────────────────────────────
set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_SOURCE_DIR}/packaging/rpm/changelog")

# ── Debug package ──────────────────────────────────────────────────────
set(CPACK_RPM_DEBUGINFO_PACKAGE "ON")
set(CPACK_STRIP_FILES "")

# ── Compression ────────────────────────────────────────────────────────
set(CPACK_RPM_COMPRESSION_TYPE "zstd")
set(CPACK_RPM_COMPRESSION_LEVEL "19")

# ── File permissions and ownership ─────────────────────────────────────
set(CPACK_RPM_DEFAULT_FILE_PERMISSIONS "0644")
set(CPACK_RPM_DEFAULT_DIR_PERMISSIONS "0755")

# ── Exclude from package ───────────────────────────────────────────────
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST "/usr/include;/usr/lib/cmake;/usr/share/doc")

# ── User/Group for systemd service ─────────────────────────────────────
set(CPACK_RPM_USER "root")
set(CPACK_RPM_GROUP "root")

# ── Enable RPM generator ───────────────────────────────────────────────
list(APPEND CPACK_GENERATOR "RPM")