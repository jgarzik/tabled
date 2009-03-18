Name:           tabled
Version:        0.3git
Release:        1%{?dist}
Summary:        Distributed key/value table service

Group:          System Environment/Base
License:        GPLv2
URL:            http://www.kernel.org/pub/software/network/distsrv/
Source0:        tabled-0.3git.1234abc.tar.gz
Source2:        tabled.init
Source3:        tabled.sysconf
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  db4-devel libevent-devel glib2-devel

%description
Distributed key/value table service

%package devel
Summary: Header files, libraries and development documentation for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
This package contains the header files, static libraries and development
documentation for %{name}. If you like to develop programs using %{name},
you will need to install %{name}-devel.

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

mkdir -p %{buildroot}%{_sysconfdir}/rc.d/init.d
install -m 755 %{SOURCE2} %{buildroot}%{_sysconfdir}/rc.d/init.d/tabled

mkdir -p %{buildroot}/etc/sysconfig
install -m 755 %{SOURCE3} %{buildroot}/etc/sysconfig/tabled

%check
make -s check

%clean
rm -rf $RPM_BUILD_ROOT

%post
# must be in chkconfig on
/sbin/chkconfig --add tabled

%preun
if [ "$1" = 0 ] ; then
	/sbin/service tabled stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del tabled
fi

%postun
if [ "$1" -ge "1" ]; then
	/sbin/service tabled condrestart >/dev/null 2>&1 ||:
fi

%files
%defattr(-,root,root,-)
%doc README NEWS doc/*.txt
%{_sbindir}/tabled
%{_sbindir}/tdbadm
%attr(0755,root,root)           %{_sysconfdir}/rc.d/init.d/tabled
%attr(0644,root,root)           %{_sysconfdir}/sysconfig/tabled

%files devel
%defattr(-,root,root,0644)
%{_includedir}/*.h

%changelog
* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-1%{?dist}
- initial release

