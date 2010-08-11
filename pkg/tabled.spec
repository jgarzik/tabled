Name:		tabled
Version:	0.5.1
Release:	1%{?dist}
Summary:	Distributed key/value table service

Group:		System Environment/Base
License:	GPLv2
URL:		http://hail.wiki.kernel.org/

# pulled from upstream git, commit 33595340bc7ed226623baf75a9ccdabfc2a47a7f
# to recreate tarball, check out commit, then run "make dist"
Source0:	tabled-%{version}git.tar.gz

#uncomment this, if a full release version of tabled
#Source0:	http://www.kernel.org/pub/software/network/distsrv/tabled/tabled-%{version}.tar.gz

Source2:	tabled.init
Source3:	tabled.sysconf
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# N.B. We need chunkd and cld to build, because our "make check" spawns
# private copies of infrastructure daemons.
BuildRequires:	db4-devel libevent-devel glib2-devel pcre-devel
BuildRequires:	chunkd cld libcurl-devel libxml2-devel
BuildRequires:	procps
BuildRequires:	hail-devel >= 0.7

Requires:	cld >= 0.7
Requires:	chunkd >= 0.7

%description
tabled provides an infinitely scalable, lexicographically sorted
key/value look-up table. Keys cannot exceed 1024 bytes; values can be
any size, including several gigabytes or more.

tabled user interface is HTTP REST, and is intended to be compatible with
existing Amazon S3 clients.


%prep
%setup -q -n tabled-0.5.1git


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
%attr(0755,root,root)	%{_initddir}/tabled
%config(noreplace)	%{_sysconfdir}/sysconfig/tabled

%changelog
* Wed Aug 11 2010 Jeff Garzik <jgarzik@redhat.com> - 0.5.1-1
- Update for release v0.5.1

* Thu Jul 15 2010 Jeff Garzik <jgarzik@redhat.com> - 0.5.1-0.2.g33595340
- BR: libxml2-devel

* Thu Jul 15 2010 Jeff Garzik <jgarzik@redhat.com> - 0.5.1-0.1.g33595340
- add sources for git commit 33595340bc7ed226623baf75a9ccdabfc2a47a7f
- build against newly consolidated 'hail' pkg
- removed now-unneeded tabled-devel RPM

* Mon Jun 28 2010 Pete Zaitce <zaitcev@redhat.com> - 0.5-0.7.m1
- Revert to a staggered start in start-daemon
- Test build, bump to 0.5-0.7.m1 (from 0.5-0.7.g091d6a5d)

* Mon Apr 19 2010 Jeff Garzik <jgarzik@redhat.com> - 0.5-0.7.g091d6a5d
- add sources for git commit 091d6a5df9d9381958db35cc3a215dc3bc26c380

* Wed Apr 14 2010 Jeff Garzik <jgarzik@redhat.com> - 0.5-0.6.gc2310915
- add sources for git commit c2310915e838aa0da85c86a53d87a41a3213785c

* Mon Feb 15 2010 Jeff Garzik <jgarzik@redhat.com> - 0.5-0.5.gcaf7da1e
- add sources for git commit caf7da1e7bba1125d846fc1625793134d851917b

* Fri Feb  5 2010 Jeff Garzik <jgarzik@redhat.com> - 0.5-0.4.g5e1a96f0
- add sources for git commit 5e1a96f00f5d203f24d1a93d6dc5d3224f881aee

* Wed Dec 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.5-0.3.ge32562b9
- add sources for git commit e32562b95234a8c221b8a91e8712878ea05cd6b9

* Tue Dec 15 2009 Jeff Garzik <jgarzik@redhat.com> - 0.5-0.2.g93f17fe1
- add sources for git commit 93f17fe1396082762447a772287ce9b6b40d389b

* Mon Nov 30 2009 Jeff Garzik <jgarzik@redhat.com> - 0.5-0.1.g26571e40
- add sources for git commit 26571e40570dfb0d0fc69507cbe8386e65252ff8

* Fri Nov 13 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-1
- upstream release v0.4

* Thu Nov  5 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.5.gea96d7d5
- add sources for git commit ea96d7d54f3bbebf52436a4a1c5de3e85ed7effd

* Fri Oct 02 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.4.ge1c9069b
- add sources for git commit e1c9069b3604e9c9e2946db80101d456598fef82

* Wed Sep 30 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.3.g784b42ad
- add sources for git commit 784b42ad5cd766450c4df93cfb7f91605708dcb1

* Tue Sep 29 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.2.g0c7f54dc
- add sources for git commit 0c7f54dcdb057ba46e7f8406695cd66bfc70b0f2

* Tue Sep 29 2009 Jeff Garzik <jgarzik@redhat.com> - 0.4-0.1.g0c7f54dc
- update to git commit 0c7f54dcdb057ba46e7f8406695cd66bfc70b0f2

* Mon Sep 28 2009 Pete Zaitcev <zaitcev@redhat.com> - 0.3-6
- Drop ExcludeArch, fixed in bz#514651.

* Sat Sep 05 2009 Caolán McNamara <caolanm@redhat.com> - 0.3-5
- rebuild for dependencies

* Thu Aug 27 2009 Warren Togami <wtogami@redhat.com> - 0.3-4
- rebuild

* Wed Aug 26 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-3
- require/rebuild for cld 0.2.1

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 0.3-2
- rebuilt with new openssl

* Sat Aug 15 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-1
- update to release version 0.3

* Wed Aug 12 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.11.g7f6a0b63
- update to git commit 7f6a0b639167eb64adf223d9f38d13c61e4ff185

* Sat Aug  8 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.10.ge1ef4104
- update to git commit e1ef4104ba859f251c9976d1e2afd3e0d9317067

* Fri Aug  7 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.9.g20e56358
- update to git commit 20e56358d9320fc73ef2ecc689be960c9be91805

* Wed Jul 29 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.8.g0b3ec75c
- update to git commit 0b3ec75c239e231ee2af8252466ec4fd9da2bd7c

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.3-0.7.gebb1144c
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Jul 23 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.6.gebb1144c
- update to git commit ebb1144ceefd7a936acafc79c6e274095bd0bb06
- BuildRequires: procps

* Tue Jul 21 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.5.g8102bcda
- rebuild for koji silliness

* Tue Jul 21 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.4.g8102bcda
- update to git commit 8102bcda428a9c2d9647d33f21ede6764a514c6e

* Tue Jul 21 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.3.g6f015fa5
- BuildRequires: libcurl-devel

* Sun Jul 19 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.2.g6f015fa5
- update to git commit 6f015fa5f920da809d66e57515672b26d0e82b89
- expanded description
- describe source tarball regen, per pkg guidelines

* Fri Jul 17 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3-0.1.g2783d260
- new release version scheme

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-5
- chkconfig default off
- add docs: COPYING, LICENSE
- config(noreplace) sysconfig/tabled

* Thu Jul 16 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-4
- minor spec updates for review feedback, Fedora packaging guidelines

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-3
- rename lib to libhttpstor

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-2
- package and ship libs3c

* Wed Mar 18 2009 Jeff Garzik <jgarzik@redhat.com> - 0.3git-1
- initial release

