%global git 3c0b9780ffab0d93b14075333fd042fc183f3ce7

Name:           php-fkooman-oauth2-client
Version:        7.2.1
Release:        0.1%{?dist}
Summary:        Opinionated OAuth 2.0 client

License:        MIT
URL:            https://software.tuxed.net/php-oauth2-client
%if %{defined git}
Source0:        https://git.tuxed.net/fkooman/php-oauth2-client/snapshot/php-oauth2-client-%{git}.tar.xz
%else
Source0:        https://software.tuxed.net/php-oauth2-client/files/php-oauth2-client-%{version}.tar.xz
Source1:        https://software.tuxed.net/php-oauth2-client/files/php-oauth2-client-%{version}.tar.xz.minisig
Source2:        minisign-8466FFE127BCDC82.pub
%endif

BuildArch:      noarch

BuildRequires:  minisign
BuildRequires:  php-fedora-autoloader-devel
BuildRequires:  %{_bindir}/phpab
#    "require-dev": {
#        "phpunit/phpunit": "^4.8.35|^5|^6|^7"
#    },
%if 0%{?fedora} >= 28 || 0%{?rhel} >= 8
BuildRequires:  phpunit7
%global phpunit %{_bindir}/phpunit7
%else
BuildRequires:  phpunit
%global phpunit %{_bindir}/phpunit
%endif
#    "require": {
#        "ext-curl": "*",
#        "ext-date": "*",
#        "ext-hash": "*",
#        "ext-json": "*",
#        "ext-pcre": "*",
#        "ext-pdo": "*",
#        "ext-session": "*",
#        "ext-spl": "*",
#        "paragonie/constant_time_encoding": "^1|^2",
#        "paragonie/random_compat": ">=1",
#        "php": ">=5.4",
#        "psr/log": "^1.0",
#        "symfony/polyfill-php56": "^1"
#    },
BuildRequires:  php(language) >= 5.4.0
BuildRequires:  php-curl
BuildRequires:  php-date
BuildRequires:  php-hash
BuildRequires:  php-json
BuildRequires:  php-pcre
BuildRequires:  php-pdo
BuildRequires:  php-session
BuildRequires:  php-spl
BuildRequires:  php-composer(paragonie/constant_time_encoding)
BuildRequires:  php-composer(psr/log)
%if 0%{?fedora} < 28 && 0%{?rhel} < 8
BuildRequires:  php-composer(paragonie/random_compat)
BuildRequires:  php-composer(symfony/polyfill-php56)
%endif

#    "require": {
#        "ext-curl": "*",
#        "ext-date": "*",
#        "ext-hash": "*",
#        "ext-json": "*",
#        "ext-pcre": "*",
#        "ext-pdo": "*",
#        "ext-session": "*",
#        "ext-spl": "*",
#        "paragonie/constant_time_encoding": "^1|^2",
#        "paragonie/random_compat": ">=1",
#        "php": ">=5.4",
#        "psr/log": "^1.0",
#        "symfony/polyfill-php56": "^1"
#    },
Requires:       php(language) >= 5.4.0
Requires:       php-curl
Requires:       php-date
Requires:       php-hash
Requires:       php-json
Requires:       php-pcre
Requires:       php-pdo
Requires:       php-session
Requires:       php-spl
Requires:       php-composer(paragonie/constant_time_encoding)
Requires:       php-composer(psr/log)
%if 0%{?fedora} < 28 && 0%{?rhel} < 8
Requires:       php-composer(paragonie/random_compat)
Requires:       php-composer(symfony/polyfill-php56)
%endif

Provides:       php-composer(fkooman/oauth2-client) = %{version}

%description
The project provides an opinionated OAuth 2.0 client library for integration 
in your own application. It has minimal dependencies, but still tries to be 
secure. The main purpose is to be as simple as possible whilst being secure.

%prep
%if %{defined git}
%autosetup -n php-oauth2-client-%{git}
%else
/usr/bin/minisign -V -m %{SOURCE0} -x %{SOURCE1} -p %{SOURCE2}
%autosetup -n php-oauth2-client-%{version}
%endif

%build
%{_bindir}/phpab -t fedora -o src/autoload.php src
cat <<'AUTOLOAD' | tee -a src/autoload.php
require_once '%{_datadir}/php/ParagonIE/ConstantTime/autoload.php';
require_once '%{_datadir}/php/Psr/Log/autoload.php';
AUTOLOAD
%if 0%{?fedora} < 28 && 0%{?rhel} < 8
cat <<'AUTOLOAD' | tee -a src/autoload.php
require_once '%{_datadir}/php/random_compat/autoload.php';
require_once '%{_datadir}/php/Symfony/Polyfill/autoload.php';
AUTOLOAD
%endif

%install
mkdir -p %{buildroot}%{_datadir}/php/fkooman/OAuth/Client
cp -pr src/* %{buildroot}%{_datadir}/php/fkooman/OAuth/Client

%check
%{_bindir}/phpab -o tests/autoload.php tests
cat <<'AUTOLOAD' | tee -a tests/autoload.php
require_once 'src/autoload.php';
AUTOLOAD

%{phpunit} tests --verbose --bootstrap=tests/autoload.php

%files
%license LICENSE
%doc composer.json CHANGES.md README.md
%dir %{_datadir}/php/fkooman
%dir %{_datadir}/php/fkooman/OAuth
%{_datadir}/php/fkooman/OAuth/Client

%changelog
* Mon Apr 27 2020 François Kooman <fkooman@tuxed.net> - 7.2.1-0.1
- update to 7.2.1

* Sat Apr 25 2020 François Kooman <fkooman@tuxed.net> - 7.2.0-1
- update to 7.2.0
