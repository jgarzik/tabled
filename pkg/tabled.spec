Name:		tabled
Version:	0.3
Release:	0.1.g2783d260%{?dist}
Summary:	Distributed key/value table service

Group:		System Environment/Base
License:	GPLv2
URL:		http://hail.wiki.kernel.org/

# pulled from upstream git, commit 2783d2605317c611a051784a71c48383f21c6b9c
Source0:	tabled-%{version}git.tar.gz
Source2:	tabled.init
Source3:	tabled.sysconf
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# N.B. We need chunkd and cld to build, because our "make check" spawns
# private copies of infrastructure daemons.
BuildRequires:	db4-devel libevent-devel glib2-devel pcre-devel
BuildRequires:	chunkd chunkd-devel cld cld-devel

# cld is broken on big-endian... embarrassing!!!
# FIXME: remove this when cld is fixed
ExcludeArch:	ppc ppc64

%description
Distributed key/value table service

%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.

%prep
%setup -q -n %{name}-%{version}git


%build
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}%{_initddir}
install -m 755 %{SOURCE2} %{buildroot}%{_initddir}/tabled

mkdir -p %{buildroot}%{_sysconfdir}/sysconfig
install -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/sysconfig/tabled

find %{buildroot} -name '*.la' -exec rm -f {} ';'

%check
make -s check

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
# must be in chkconfig on
/sbin/chkconfig --add tabled

%preun
if [ "$1" = 0 ] ; then
	/sbin/service tabled stop >/dev/null 2>&1 ||:
	/sbin/chkconfig --del tabled
fi

%postun
/sbin/ldconfig
if [ "$1" -ge "1" ]; then
	/sbin/service tabled condrestart >/dev/null 2>&1 ||:
fi

%files
%defattr(-,root,root,-)
%doc AUTHORS COPYING LICENSE README NEWS doc/*.txt
%{_sbindir}/tabled
%{_sbindir}/tdbadm
%{_libdir}/*.so.*
%attr(0755,root,root)	%{_initddir}/tabled
%config(noreplace)	%{_sysconfdir}/sysconfig/tabled

%files devel
%defattr(-,root,root,-)
%{_libdir}/lib*.so
%{_libdir}/pkgconfig/*
%{_includedir}/*

%changelog
* Fri Jul 17 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.1.g2783d260%{?dist}
- new release version scheme

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-5%{?dist}
- chkconfig default off
- add docs: COPYING, LICENSE
- config(noreplace) sysconfig/tabled

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-4%{?dist}
- minor spec updates for review feedback, Fedora packaging guidelines

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-3%{?dist}
- rename lib to libhttpstor

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-2%{?dist}
- package and ship libs3c

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-1%{?dist}
- initial release

