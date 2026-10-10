# vim: sw=4:ts=4:et


%define relabel_files() \
restorecon -R /usr/bin/penguin; \
restorecon -R /usr/lib/systemd/system/rusty-penguin.service; \

%define selinux_policyver 42.1.18-4

Name:   rusty-penguin_selinux
Version:	1.0
Release:	1%{?dist}
Summary:	SELinux policy module for rusty-penguin

Group:	System Environment/Base
License:	GPLv2+
URL:		http://github.com/myzhang1029/penguin-rs.git
Source0:	rusty-penguin.pp
Source1:	rusty-penguin.if
Source2:	rusty_penguin_selinux.8


Requires: policycoreutils-python-utils, libselinux-utils
Requires(post): selinux-policy-base >= %{selinux_policyver}, policycoreutils-python-utils
Requires(postun): policycoreutils-python-utils
Requires(post): rusty-penguin
BuildArch: noarch

%description
This package installs and sets up the  SELinux policy security module for rusty-penguin.

%install
install -d %{buildroot}%{_datadir}/selinux/packages
install -m 644 %{SOURCE0} %{buildroot}%{_datadir}/selinux/packages
install -d %{buildroot}%{_datadir}/selinux/devel/include/contrib
install -m 644 %{SOURCE1} %{buildroot}%{_datadir}/selinux/devel/include/contrib/
install -d %{buildroot}%{_mandir}/man8/
install -m 644 %{SOURCE2} %{buildroot}%{_mandir}/man8/rusty_penguin_selinux.8
install -d %{buildroot}/etc/selinux/targeted/contexts/users/


%post
semodule -n -i %{_datadir}/selinux/packages/rusty-penguin.pp

if [ $1 -eq 1 ]; then

fi
if /usr/sbin/selinuxenabled ; then
    /usr/sbin/load_policy
    %relabel_files
fi;
exit 0

%postun
if [ $1 -eq 0 ]; then

    semodule -n -r rusty-penguin
    if /usr/sbin/selinuxenabled ; then
       /usr/sbin/load_policy
       %relabel_files
    fi;
fi;
exit 0

%files
%attr(0600,root,root) %{_datadir}/selinux/packages/rusty-penguin.pp
%{_datadir}/selinux/devel/include/contrib/rusty-penguin.if
%{_mandir}/man8/rusty_penguin_selinux.8.*


%changelog
* Sat Oct 10 2026 Zhang Maiyun <me@maiyun.me> 1.0-1
- Initial version

