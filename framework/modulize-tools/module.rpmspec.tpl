Name: lib%{MODULE_NAME}
Version: %{MODULE_VERSION}
Release: 1%{?dist}
Summary: navi module %{MODULE_NAME} lib.
License: 1verge
URL: http://www.lverge.com/
Group: Development/Libraries

Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: libcnavi-devel >= 0.4.0
Requires:      libcnavi >= 0.4.0

%define _unpackaged_files_terminate_build 0

%description
lib%{MODULE_NAME} library is licensed under the `lverge license`_; see LICENSE in the
source distribution for details.

%prep

%setup

%build
./configure --libdir=%{_libdir}/cnavimodules
make

%install
make install DESTDIR=$RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/etc/cnavi/
cp -f %{MODULE_NAME}.json $RPM_BUILD_ROOT/etc/cnavi/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/cnavimodules/lib%{MODULE_NAME}.so*
%config(noreplace) %{_sysconfdir}/cnavi/%{MODULE_NAME}.json

%changelog
* Mon Apr 23 2012 zhang yufeng <zhangyufeng@youku.com>
- Wrote session.spec.

