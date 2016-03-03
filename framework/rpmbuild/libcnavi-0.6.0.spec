Name: libcnavi
Version: 0.6.0
Release: 2%{?dist}
Summary: libcnavi lib.
License: 1verge
URL: http://www.lverge.com/
Group: Development/Libraries

Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires:  jansson >= 2.6,jansson-devel >= 2.6
Requires:      jansson >= 2.6 

%define _unpackaged_files_terminate_build 0

%description
libcnavi library is licensed under the `lverge license`; 
see LICENSE in the source distribution for details.
libcnavi is a application development framework which bases on
web-server engine (nginx etc).

%package devel
Summary: Headers and libraries for cnavi app-module development.
Group: Development/Libraries
#BuildRequires:  jansson-devel >= 1.3, jansson >= 1.3
Requires:       libcnavi >= 0.6.0 ,jansson-devel >= 2.6

%description devel
This package provides cnavi static library and header files needed
to develop.

%package driver
Summary: cnavi-driver-specific libraries .
Group: Development/Libraries
#BuildRequires:  jansson-devel >= 1.3, jansson >= 1.3
Requires:       libcnavi >= 0.6.0 ,jansson >= 2.6

%description driver

%package driver-devel
Summary: cnavi-driver-specific headers and libraries.
Group: Development/Libraries
#BuildRequires:  jansson-devel >= 1.3, jansson >= 1.3
Requires:       libcnavi-driver >= 0.6.0, jansson-devel >= 2.6

%description driver-devel

%package nrscheck
Summary: cnavi-nrscheck-specific headers and libraries.
Group: Development/Libraries
#BuildRequires:  jansson-devel >= 1.3, jansson >= 1.3
Requires:       libcnavi >= 0.6.0, jansson >= 2.6

%description nrscheck

%package util
Summary: cnavi-util-specific headers and libraries.
Group: Development/Libraries
%if 0%{?rhel} == 6
Requires:       libcnavi >= 0.6.0, libcurl >= 7.27.0
%else
Requires:       libcnavi >= 0.6.0, libcurl4 >= 7.27.0
%endif

%description util

%package util-devel
Summary: cnavi-util-specific headers and libraries.
Group: Development/Libraries
%if 0%{?rhel} == 6
Requires:       libcnavi >= 0.6.0, libcurl >= 7.27.0
%else
Requires:       libcnavi-util >= 0.6.0, libcurl4 >= 7.27.0
%endif

%description util-devel

%prep

%setup

%build
./configure --libdir=%{_libdir} --includedir=%{_includedir} --enable-debug
make

%install
make install DESTDIR=$RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi/upgroups
mkdir -p $RPM_BUILD_ROOT/%{_datadir}/cnavi/modulize_tools
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/cnavimodules
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/cnavimodules/upgroups
cp -f ./conf/navi.json $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi
cp -f ./conf/app.json.example $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi
cp -f ./conf/prev_app_basic.json.example $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi
cp -f ./conf/post_app_basic.json.example $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi
cp -f ./conf/nrscheck.json $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi
cp -f ./modulize-tools/* $RPM_BUILD_ROOT/%{_datadir}/cnavi/modulize_tools
cp -f ./conf/upgroup_common.json $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi/upgroups/common.json
cp -f ./conf/redis_group.json.example $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi/upgroups
cp -f ./conf/redis_group_repl_set.json.example $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi/upgroups
cp -f ./conf/http_group.json.example $RPM_BUILD_ROOT/%{_sysconfdir}/cnavi/upgroups
mv $RPM_BUILD_ROOT/%{_libdir}/libcnavipolicy.* $RPM_BUILD_ROOT/%{_libdir}/cnavimodules/upgroups
mv $RPM_BUILD_ROOT/%{_libdir}/libnrscheck.so* $RPM_BUILD_ROOT/%{_libdir}/cnavimodules

%clean
rm -rf $RPM_BUILD_ROOT

%pre
id cnavi
if [ $? -ne 0 ];then
	groupadd cnavi
	%{_sbindir}/useradd -c "cnavi user" -s /bin/false -r -M -g cnavi cnavi 2>/dev/null
fi


%files
%defattr(-,root,root,-)
%{_libdir}/libcnavi.so.*
%{_libdir}/cnavimodules/upgroups/libcnavipolicy.so
%{_libdir}/cnavimodules/upgroups/libcnavipolicy.so.*
%config(noreplace) %{_sysconfdir}/cnavi/navi.json
%{_sysconfdir}/cnavi/app.json.example
%{_sysconfdir}/cnavi/prev_app_basic.json.example
%{_sysconfdir}/cnavi/post_app_basic.json.example
%config(noreplace) %{_sysconfdir}/cnavi/upgroups/common.json
%{_sysconfdir}/cnavi/upgroups/http_group.json.example
%{_sysconfdir}/cnavi/upgroups/redis_group.json.example
%{_sysconfdir}/cnavi/upgroups/redis_group_repl_set.json.example
%attr(0755,root,root) %dir %{_libdir}/cnavimodules

%files devel
%defattr(-,root,root,-)
%{_includedir}/cnavi/*.h
%{_includedir}/cnaviproxy/*.h
%{_includedir}/cnavitask/*.h
%{_includedir}/cnaviutil/*.h
%{_libdir}/libcnavi.so
%{_libdir}/libcnavi.la
%{_libdir}/libcnavi.a
%{_libdir}/cnavimodules/upgroups/libcnavipolicy.la
%{_libdir}/cnavimodules/upgroups/libcnavipolicy.a
%{_libdir}/pkgconfig/libcnavi.*
%attr(0755,cnavi,cnavi) %dir %{_datadir}/cnavi/
%attr(0777,cnavi,cnavi) %dir %{_datadir}/cnavi/modulize_tools/
%attr(-,cnavi,cnavi) %{_datadir}/cnavi/modulize_tools/*

%files driver
%defattr(-,root,root,-)
%{_libdir}/libcnavidriver.so.*

%files driver-devel
%defattr(-,root,root,-)
%{_includedir}/cnavidriver/*.h
%{_libdir}/libcnavidriver.so
%{_libdir}/libcnavidriver.la
%{_libdir}/libcnavidriver.a
%{_libdir}/pkgconfig/libcnavidriver.*

%files nrscheck
%defattr(-,root,root,-)
%{_libdir}/cnavimodules/libnrscheck.so*
%config(noreplace) %{_sysconfdir}/cnavi/nrscheck.json


%files util
%defattr(-,root,root,-)
%{_libdir}/libcnaviutil.so.*

%files util-devel
%defattr(-,root,root,-)
%{_includedir}/cnaviutil/*.h
%{_libdir}/libcnaviutil.so
%{_libdir}/libcnaviutil.la
%{_libdir}/libcnaviutil.a

%changelog
* Mon Apr 23 2012 zhang yufeng <zhangyufeng@youku.com>
- Wrote session.spec.
