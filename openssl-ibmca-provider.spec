%global modulesdir %(openssl version -m | grep -o '".*"' | tr -d '"')
# Above can be replaced by the following once OpenSSL commit 
# https://github.com/openssl/openssl/commit/7fde39de848f062d6db45bf9e69439db2100b9bb
# has been included into the distribution:
# %global modulesdir %(pkg-config --variable=modulesdir libcrypto)

Name:       openssl-ibmca
Version:    2.5.0
Release:    1%{?dist}
Summary:    An IBMCA OpenSSL dynamic provider

License:    ASL 2.0
URL:        https://github.com/opencryptoki/openssl-ibmca
Source0:    https://github.com/opencryptoki/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz

Requires:       openssl >= 3.0.0 libica >= 4.0.1
BuildRequires:  openssl-devel >= 3.0.0 libica-devel >= 4.0.1 openssl >= 3.0.0
BuildRequires:  autoconf automake libtool perl

ExclusiveArch: s390 s390x

%description
This package contains a shared object OpenSSL dynamic provider which interfaces 
to libica-cex, a library enabling the IBM s390x crypto instructions.

%prep
%setup -q -n %{name}-%{version}

./bootstrap.sh

%build
%configure --libdir=%{modulesdir} --disable-engine --enable-provider
%make_build

%install
%make_install
rm -f $RPM_BUILD_ROOT%{modulesdir}/ibmca-provider.la
mv -f src/provider/openssl.cnf.sample src/provider/openssl.cnf.sample.%{_arch}

%files
%license LICENSE
%doc ChangeLog README.md src/provider/openssl.cnf.sample.%{_arch} src/provider/ibmca-provider-opensslconfig
%{modulesdir}/ibmca-provider.so
%{_mandir}/man5/ibmca-provider.5*
%dir %attr(777,root,root) %{_localstatedir}/log/ibmca

%changelog
* Thu Mar 30 2023 Ingo Franzki <ifranzki@linux.ibm.com> 2.4.0
- Update Version

* Fri Sep 30 2022 Juergen Christ <jchrist@linux.ibm.com> 2.3.1
- Adjust to libica 4.1.0

* Fri Mar 25 2022 Juergen Christ <jchrist@linux.ibm.com> 2.3.0
- First version including the provider
- Fix for engine build without OpenSSL 3.0 sources

* Wed March 3 2022 Ingo Franzki <ifranzki@linux.ibm.com>
- Add provider support

* Thu Mar 10 2022 Juergen Christ <jchrist@linux.ibm.com> 2.2.3
- Update Version
* Thu Jan 27 2022 Juergen Christ <jchrist@linux.ibm.com> 2.2.2
- Update Version

* Mon Sep 13 2021 Juergen Christ <jchrist@linux.ibm.com> 2.2.1
- Update Version

* Wed May 19 2021 Juergen Christ <jchrist@linux.ibm.com> 2.2.0
- Update Version

* Wed May 19 2021 Juergen Christ <jchrist@linux.ibm.com> 2.1.3
- Update Version

* Wed Apr 28 2021 Juergen Christ <jchrist@linux.ibm.com> 2.1.2
- Update Version

* Tue May 05 2020 Patrick Steuer <patrick.steuer@de.ibm.com> 2.1.1
- Update Version

* Mon Sep 09 2019 Patrick Steuer <patrick.steuer@de.ibm.com> 2.1.0
- Update Version

* Tue Apr 23 2019 Patrick Steuer <patrick.steuer@de.ibm.com> 2.0.3
- Update Version

* Tue Nov 27 2018 Patrick Steuer <patrick.steuer@de.ibm.com> 2.0.2
- Update Version

* Thu Nov 08 2018 Patrick Steuer <patrick.steuer@de.ibm.com> 2.0.1
- Update Version

* Wed Jun 06 2018 Eduardo Barretto <ebarretto@linux.vnet.ibm.com> 2.0.0
- Update Version
- Update libica version required for building ibmca

* Wed Feb 21 2018 Eduardo Barretto <ebarretto@linux.vnet.ibm.com> 1.4.1
- Updated to 1.4.1

* Thu Jan 25 2018 Eduardo Barretto <ebarretto@linux.vnet.ibm.com>
- Update engine filename
- Spec cleanup

* Thu Oct 26 2017 Patrick Steuer <patrick.steuer@de.ibm.com>
- Fix build warning about comma and newlines
- Remove INSTALL file from doc
- Fix README name on doc

* Fri Sep 8 2017 Paulo Vital <pvital@linux.vnet.ibm.com> 1.4.0
- Update new License
- Update Source and URL pointing to GitHub
- Added support to AES-GCM
- Fix bugs/issues

* Fri Feb 17 2017 Paulo Vital <pvital@linux.vnet.ibm.com> 1.3.1
- Support OpenSSL-1.1 and older versions

* Tue Dec 1 2015 Claudio Carvalho <cclaudio@br.ibm.com> 1.3.0
- openssl-ibmca-1.3.0 release

* Mon May 2 2011 Kent Yoder <yoder1@us.ibm.com> 1.2.0
- updates for s390 MSA4 features, engine version 1.2

* Fri Mar 17 2006 Michael A. Halcrow <mhalcrow@us.ibm.com> 1.0.0
- initial version
