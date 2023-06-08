#### Results

This stuff is very hacky at the moment - it was hacked together in an afternoon!

Update @ 11-June-2023: Our SBOMs are now directly scannable by Trivy!

Here is a scan of the `chiselled stunnel` container image.

```
$ trivy sbom base_image_stunnel_sbom.json
2023-06-15T23:23:51.606+0530	INFO	Vulnerability scanning is enabled
2023-06-15T23:23:51.607+0530	INFO	Detected SBOM format: spdx-json
2023-06-15T23:23:51.614+0530	INFO	Detected OS: ubuntu
2023-06-15T23:23:51.614+0530	INFO	Detecting Ubuntu vulnerabilities...
2023-06-15T23:23:51.615+0530	INFO	Number of language-specific files: 0

base_image_stunnel_sbom.json (ubuntu 23.04)

Total: 1 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

┌─────────┬────────────────┬──────────┬───────────────────┬───────────────┬────────────────────────────────────────────────────────────┐
│ Library │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │                           Title                            │
├─────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ libc6   │ CVE-2016-20013 │ LOW      │ 2.37-0ubuntu2     │               │ sha256crypt and sha512crypt through 0.6 allow attackers to │
│         │                │          │                   │               │ cause a denial of...                                       │
│         │                │          │                   │               │ https://avd.aquasec.com/nvd/cve-2016-20013                 │
└─────────┴────────────────┴──────────┴───────────────────┴───────────────┴────────────────────────────────────────────────────────────┘
```

This CVE (`CVE-2016-20013`) is actually NOT considered a problem, and is
`Deferred` in the Ubuntu Security Tracker.

References:

- https://security.snyk.io/vuln/SNYK-UNMANAGED-GLIBC-2408039
- https://ubuntu.com/security/CVE-2016-20013

Other vendors (like Chainguard) have simply ignored CVE-2016-20013 it seems!


```
$ rm ~/.cache/trivy/fanal/fanal.db; trivy sbom our_actual_auto_generated_sbom.json
2023-06-11T17:24:06.220+0530	INFO	Vulnerability scanning is enabled
2023-06-11T17:24:06.222+0530	INFO	Detected SBOM format: spdx-json
2023-06-11T17:24:06.233+0530	INFO	Detected OS: ubuntu
2023-06-11T17:24:06.233+0530	INFO	Detecting Ubuntu vulnerabilities...
2023-06-11T17:24:06.234+0530	INFO	Number of language-specific files: 0

our_actual_auto_generated_sbom.json (ubuntu 22.04)

Total: 4 (UNKNOWN: 0, LOW: 3, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

┌──────────┬────────────────┬──────────┬────────────────────┬───────────────┬────────────────────────────────────────────────────────────┐
│ Library  │ Vulnerability  │ Severity │ Installed Version  │ Fixed Version │                           Title                            │
├──────────┼────────────────┼──────────┼────────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ libc6    │ CVE-2016-20013 │ LOW      │ 2.35-0ubuntu3      │               │ sha256crypt and sha512crypt through 0.6 allow attackers to │
│          │                │          │                    │               │ cause a denial of...                                       │
│          │                │          │                    │               │ https://avd.aquasec.com/nvd/cve-2016-20013                 │
├──────────┼────────────────┼──────────┼────────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ libcap2  │ CVE-2023-2603  │ MEDIUM   │ 1:2.44-1build3     │               │ Integer Overflow in _libcap_strdup()                       │
│          │                │          │                    │               │ https://avd.aquasec.com/nvd/cve-2023-2603                  │
│          ├────────────────┼──────────┤                    ├───────────────┼────────────────────────────────────────────────────────────┤
│          │ CVE-2023-2602  │ LOW      │                    │               │ Memory Leak on pthread_create() Error                      │
│          │                │          │                    │               │ https://avd.aquasec.com/nvd/cve-2023-2602                  │
├──────────┼────────────────┤          ├────────────────────┼───────────────┼────────────────────────────────────────────────────────────┤
│ libzstd1 │ CVE-2022-4899  │          │ 1.4.8+dfsg-3build1 │               │ buffer overrun in util.c                                   │
│          │                │          │                    │               │ https://avd.aquasec.com/nvd/cve-2022-4899                  │
└──────────┴────────────────┴──────────┴────────────────────┴───────────────┴────────────────────────────────────────────────────────────┘
```

Regular `ubuntu:latest` base image:

```
$ trivy image ubuntu:latest
2023-06-11T22:55:14.544+0530	INFO	Vulnerability scanning is enabled
2023-06-11T22:55:14.544+0530	INFO	Secret scanning is enabled
2023-06-11T22:55:14.544+0530	INFO	If your scanning is slow, please try '--scanners vuln' to disable secret scanning
2023-06-11T22:55:14.544+0530	INFO	Please see also https://aquasecurity.github.io/trivy/v0.42/docs/secret/scanning/#recommendation for faster secret detection
2023-06-11T22:55:16.115+0530	INFO	Detected OS: ubuntu
2023-06-11T22:55:16.115+0530	INFO	Detecting Ubuntu vulnerabilities...
2023-06-11T22:55:16.118+0530	INFO	Number of language-specific files: 0

ubuntu:latest (ubuntu 22.04)

Total: 24 (UNKNOWN: 0, LOW: 16, MEDIUM: 8, HIGH: 0, CRITICAL: 0)
```

```
[dhiru@zippy chisel-examples]$ docker images | grep base_image
base_image_java                             22.04     715d3bff25c6   22 seconds ago   105MB
base_image                                  22.04     d07b514ab730   4 minutes ago    5.18MB
base_image_openssl                          22.04     f022822db058   5 minutes ago    10.5MB
```

Generating an SBOM for `chiselled container`:

```
$ python3 dp2json.py | jq
{
  "spdxVersion": "SPDX-2.2",
  "SPDXID": "SPDXRef-DOCUMENT",
  "dataLicense": "CC0-1.0",
  "name": "apt2sbom-zippy",
  "documentNamespace": "https://zippy/.well-known/transparency/sbom",
  "creationInfo": {
    "creators": [
      "Tool: apt2sbom-ubuntu-1.0"
    ],
    "created": "Z"
  },
  "packages": [
    {
      "name": "ubuntu:CORRUPT",
      "SPDXID": "SPDXRef-ContainerImage-XYZ"
    },
    {
      "name": "ubuntu",
      "SPDXID": "SPDXRef-OperatingSystem-XYZ",
      "versionInfo": "22.04",
      "downloadLocation": "NONE",
      "copyrightText": "",
      "primaryPackagePurpose": "OPERATING-SYSTEM"
    },
    {
      "name": "libtirpc3",
      "SPDXID": "SPDXRef-apt2sbom.libtirpc3",
      "versionInfo": "1.3.2-2ubuntu0.1",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://sourceforge.net/projects/libtirpc",
      "sourceInfo": "built package from: libtirpc3 1.3.2-2ubuntu0.1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libtirpc3@1.3.2-2ubuntu0.1?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "f2f07d1ab8ae8a8a6e893975df0bca8683caec516e7a30e8dadbb87d33aa52c4"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "472a78f8564327c4b57ddeefc14286c2270d5026"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "44522e0aedc599f75c04271b3d93d264"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/libt/libtirpc/libtirpc3_1.3.2-2ubuntu0.1_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libsystemd0",
      "SPDXID": "SPDXRef-apt2sbom.libsystemd0",
      "versionInfo": "249.11-0ubuntu3.9",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://www.freedesktop.org/wiki/Software/systemd",
      "sourceInfo": "built package from: libsystemd0 249.11-0ubuntu3.9",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libsystemd0@249.11-0ubuntu3.9?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "454c7502a1fea43c0f5566f6a2c58a66a3dae9e14e12895e89a14faa90d062b8"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "6cd976a4af7aa81aed6fe2c0376eef12190a0074"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "e175847b2692acb82c749d623c412274"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/s/systemd/libsystemd0_249.11-0ubuntu3.9_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libgcrypt20",
      "SPDXID": "SPDXRef-apt2sbom.libgcrypt20",
      "versionInfo": "1.9.4-3ubuntu3",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://directory.fsf.org/project/libgcrypt/",
      "sourceInfo": "built package from: libgcrypt20 1.9.4-3ubuntu3",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libgcrypt20@1.9.4-3ubuntu3?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "fe7d7e9f83b280f4fafaaa3852e462f43a9e854bc268e06667da2bf1b3e9d658"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "88ab282640914e091180b80d78742bf3c0dbed15"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "dcd31d109604b7cb7e159dfe1b2bfc06"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/libg/libgcrypt20/libgcrypt20_1.9.4-3ubuntu3_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libkeyutils1",
      "SPDXID": "SPDXRef-apt2sbom.libkeyutils1",
      "versionInfo": "1.6.1-2ubuntu3",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://people.redhat.com/~dhowells/keyutils/",
      "sourceInfo": "built package from: libkeyutils1 1.6.1-2ubuntu3",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libkeyutils1@1.6.1-2ubuntu3?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "940daf78ee0229549b4eabc92ffd79dd038ed96a44e2e912305a23540cf22a0a"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "cd506a6af4eb0e238ae2ba9b0bdd534042022acb"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "35376febab2ef749ccd7994c29c4370d"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/k/keyutils/libkeyutils1_1.6.1-2ubuntu3_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libgssapi-krb5-2",
      "SPDXID": "SPDXRef-apt2sbom.libgssapi-krb5-2",
      "versionInfo": "1.19.2-2ubuntu0.2",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://web.mit.edu/kerberos/",
      "sourceInfo": "built package from: libgssapi-krb5-2 1.19.2-2ubuntu0.2",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libgssapi-krb5-2@1.19.2-2ubuntu0.2?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "2b65a6566ef46cb6a4c826d6b1d138659172f0fec2a27e30d7937f650559edf9"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "07f69acffb331fdc7e2bf6ba913d2f3a0cdbc8ea"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "980f69936c6721c839345b4d64df0a2b"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/k/krb5/libgssapi-krb5-2_1.19.2-2ubuntu0.2_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "busybox-static",
      "SPDXID": "SPDXRef-apt2sbom.busybox-static",
      "versionInfo": "1:1.30.1-7ubuntu3",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://www.busybox.net",
      "sourceInfo": "built package from: busybox-static 1:1.30.1-7ubuntu3",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/busybox-static@1:1.30.1-7ubuntu3?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "3b7c609b27ceee49ae6a78ae6a0b2435c353dbbe8ffe46897b9ba2d228c4ca0d"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "27f3683969f78abcc5e691d8a38c0bbd1f51e09e"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "0c9a4be97a9fc2850adca1b6c891f8f7"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/b/busybox/busybox-static_1.30.1-7ubuntu3_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libkrb5-3",
      "SPDXID": "SPDXRef-apt2sbom.libkrb5-3",
      "versionInfo": "1.19.2-2ubuntu0.2",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://web.mit.edu/kerberos/",
      "sourceInfo": "built package from: libkrb5-3 1.19.2-2ubuntu0.2",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libkrb5-3@1.19.2-2ubuntu0.2?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "64e7d58eb86a4e00363650796915eebf781c77acd0695f8fede93f5d2233bdc5"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "dc24129f27550f3b589a2b3df78b10b580079702"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "345daa441a190a4eb763674579de006a"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/k/krb5/libkrb5-3_1.19.2-2ubuntu0.2_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "liblzma5",
      "SPDXID": "SPDXRef-apt2sbom.liblzma5",
      "versionInfo": "5.2.5-2ubuntu1",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://tukaani.org/xz/",
      "sourceInfo": "built package from: liblzma5 5.2.5-2ubuntu1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/liblzma5@5.2.5-2ubuntu1?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "8f1c46e7d3f5102a5e4fdca7c949728a343ba71c2a7c124118df2c13d4c444f7"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "13b46eb4e85a0b6d580d9049a25343980b6e561d"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "ca1b3d6332b59a4c7a9f938331d86946"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/x/xz-utils/liblzma5_5.2.5-2ubuntu1_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libc6",
      "SPDXID": "SPDXRef-apt2sbom.libc6",
      "versionInfo": "2.35-0ubuntu3.1",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://www.gnu.org/software/libc/libc.html",
      "sourceInfo": "built package from: libc6 2.35-0ubuntu3.1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libc6@2.35-0ubuntu3.1?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "f84e4f7896002f01c8e36fc3aed6f9c450974164078a87d051c2582da8634bcb"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "44792f0e04d468c6440ac00cb98a7c1ad740bdbf"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "fd3eab380955d1e259e9994d2b403f64"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.35-0ubuntu3.1_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "liblz4-1",
      "SPDXID": "SPDXRef-apt2sbom.liblz4-1",
      "versionInfo": "1.9.3-2build2",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://github.com/Cyan4973/lz4",
      "sourceInfo": "built package from: liblz4-1 1.9.3-2build2",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/liblz4-1@1.9.3-2build2?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "ac9b54d0feb840345060c74fb687675c5e1eb2b195effafae38c5f9991041e98"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "c7d04421bba9bb87f31af3237cdc109d81204fd2"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "58d698f1733da31519f22c214d1a964d"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/l/lz4/liblz4-1_1.9.3-2build2_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libcap2",
      "SPDXID": "SPDXRef-apt2sbom.libcap2",
      "versionInfo": "1:2.44-1build3",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://sites.google.com/site/fullycapable/",
      "sourceInfo": "built package from: libcap2 1:2.44-1build3",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libcap2@1:2.44-1build3?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "b772624a0c82a7b748290efcfd6ebd3ce733e6f9a5a552ebe9dadd828be1caee"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "29c6a62ab4ea77f145492761327481a3028f13ee"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "08855500d83650f8bbebae6d3e59e7c1"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/libc/libcap2/libcap2_2.44-1build3_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libssl3",
      "SPDXID": "SPDXRef-apt2sbom.libssl3",
      "versionInfo": "3.0.2-0ubuntu1.10",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://www.openssl.org/",
      "sourceInfo": "built package from: libssl3 3.0.2-0ubuntu1.10",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "1705f94b91a583e1fc1b975b42ce7f063edaf413f61169641c8ae69043a9fbbc"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "ea3b018d1739992d82776c9b6e2c459b9844e4a9"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "2cc7a1110c252795515cd3d3657f9aae"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl3_3.0.2-0ubuntu1.10_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libk5crypto3",
      "SPDXID": "SPDXRef-apt2sbom.libk5crypto3",
      "versionInfo": "1.19.2-2ubuntu0.2",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://web.mit.edu/kerberos/",
      "sourceInfo": "built package from: libk5crypto3 1.19.2-2ubuntu0.2",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libk5crypto3@1.19.2-2ubuntu0.2?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "3c75f4b4bdb99272025940021669957c273c644e6f12bbbb2db0c9388db64221"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "850eb872a04c7827cd70fe3393b200b1a4513a2f"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "d6ed257dbf849775c3b251fe80f2c6b3"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/k/krb5/libk5crypto3_1.19.2-2ubuntu0.2_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libwrap0",
      "SPDXID": "SPDXRef-apt2sbom.libwrap0",
      "versionInfo": "7.6.q-31build2",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": null,
      "sourceInfo": "built package from: libwrap0 7.6.q-31build2",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libwrap0@7.6.q-31build2?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "27eb87c90108a2e53f86efe78f00fcb701248a1b8609c26e52a9c431a41fa006"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "c1349dc7cb80c21e48e7375df1a92c87ebc3a53e"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "20ebcf9e32eb9d668ac6a32e4c0f4781"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/t/tcp-wrappers/libwrap0_7.6.q-31build2_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libgpg-error0",
      "SPDXID": "SPDXRef-apt2sbom.libgpg-error0",
      "versionInfo": "1.43-3",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://www.gnupg.org/related_software/libgpg-error/",
      "sourceInfo": "built package from: libgpg-error0 1.43-3",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libgpg-error0@1.43-3?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "1fbacdf9bd1e431cee874a697b339f6f925182bc79bba5a112b53669b33265c5"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "6cc5c7ddd12e94097167155984d75dfed9878b95"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "3a6497728e5cde7d32eccac6b557bdd9"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/libg/libgpg-error/libgpg-error0_1.43-3_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libcom-err2",
      "SPDXID": "SPDXRef-apt2sbom.libcom-err2",
      "versionInfo": "1.46.5-2ubuntu1.1",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://e2fsprogs.sourceforge.net",
      "sourceInfo": "built package from: libcom-err2 1.46.5-2ubuntu1.1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libcom-err2@1.46.5-2ubuntu1.1?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "0b432aebe830682b1a303c1bb1a48fcb92fc5dc254d067ed7309b5c818d505a5"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "fafa11a203e30f274ae262694934755707a499b2"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "b791d4717eaa25aba0a1f2cfd25b5912"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/e/e2fsprogs/libcom-err2_1.46.5-2ubuntu1.1_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "ca-certificates",
      "SPDXID": "SPDXRef-apt2sbom.ca-certificates",
      "versionInfo": "20230311ubuntu0.22.04.1",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": null,
      "sourceInfo": "built package from: ca-certificates 20230311ubuntu0.22.04.1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/ca-certificates@20230311ubuntu0.22.04.1?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "8ddd3b5d72fa144e53974d6a5782d25a0a9e1eec006118ecf2b76d53a7530f6a"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "a4a84796f7ca69f0011f6a2ad1b563c34f8fdddd"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "05fee892e9d45e65cba0c4cf3118aeb3"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20230311ubuntu0.22.04.1_all.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libnsl2",
      "SPDXID": "SPDXRef-apt2sbom.libnsl2",
      "versionInfo": "1.3.0-2build2",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://github.com/thkukuk/libnsl",
      "sourceInfo": "built package from: libnsl2 1.3.0-2build2",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libnsl2@1.3.0-2build2?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "cfeef478f96ace59617f4f93c2497776b98a33c99bf3602af46844ccf9cba9d3"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "497ba6093fa79d95d9c75dae390342b85322e2bb"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "88e25d1a32f0abf4529f5366367a4e7d"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/libn/libnsl/libnsl2_1.3.0-2build2_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "stunnel4",
      "SPDXID": "SPDXRef-apt2sbom.stunnel4",
      "versionInfo": "3:5.63-1build1",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://www.stunnel.org/",
      "sourceInfo": "built package from: stunnel4 3:5.63-1build1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/stunnel4@3:5.63-1build1?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "0a094955e7a2c825167fa0f47fade7b59bf20f314063a2dada5a5748fe85dfec"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "e7477f7b655d3c549315709c874b4fd612a39b0c"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "4d98f1c76bedd162195fcc37cfc3731e"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/universe/s/stunnel4/stunnel4_5.63-1build1_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libc6",
      "SPDXID": "SPDXRef-apt2sbom.libc6",
      "versionInfo": "2.35-0ubuntu3",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://www.gnu.org/software/libc/libc.html",
      "sourceInfo": "built package from: libc6 2.35-0ubuntu3",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libc6@2.35-0ubuntu3?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "ea9a27e0ebdd0cfc9c750d94f8074f3a35d1f97dcc77ae04c370fb498a6b6db2"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "acb061472bf9d12b2ebb1237ace2bc28843e33c9"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "a5195b20efd4841287f8c6c955af72ca"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.35-0ubuntu3_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "base-files",
      "SPDXID": "SPDXRef-apt2sbom.base-files",
      "versionInfo": "12ubuntu4.3",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": null,
      "sourceInfo": "built package from: base-files 12ubuntu4.3",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/base-files@12ubuntu4.3?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "18af705cf03053db4235c7b3a49a7bcfc729c61da0b4be6c177bfe13a6526703"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "4771161be0ce6022936147eed6a7e2a804445399"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "dcdc68c1d4f4ef9529c335767a6d0be6"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/b/base-files/base-files_12ubuntu4.3_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "base-files",
      "SPDXID": "SPDXRef-apt2sbom.base-files",
      "versionInfo": "12ubuntu4",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": null,
      "sourceInfo": "built package from: base-files 12ubuntu4",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/base-files@12ubuntu4?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "e692a0bf2e709b8a46c582a37aed657a03549539e015944987201fc0eeed14e0"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "a11907e58aea3e251875d3739f2bd91193e13659"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "f43d281a6763174cb310337af95e02cb"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/b/base-files/base-files_12ubuntu4_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libzstd1",
      "SPDXID": "SPDXRef-apt2sbom.libzstd1",
      "versionInfo": "1.4.8+dfsg-3build1",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://github.com/facebook/zstd",
      "sourceInfo": "built package from: libzstd1 1.4.8+dfsg-3build1",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libzstd1@1.4.8+dfsg-3build1?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "ae7db00ce8b093e50c994518b90203544e063b4bc574836a048bb142b950b2c9"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "434d6a9c743e3da759f96ef6d94b80b05e79162c"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "fe7fdf90c1840213bb5b944e8fb680ee"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/libz/libzstd/libzstd1_1.4.8+dfsg-3build1_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libgcc-s1",
      "SPDXID": "SPDXRef-apt2sbom.libgcc-s1",
      "versionInfo": "12.1.0-2ubuntu1~22.04",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Core developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://gcc.gnu.org/",
      "sourceInfo": "built package from: libgcc-s1 12.1.0-2ubuntu1~22.04",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libgcc-s1@12.1.0-2ubuntu1~22.04?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "0c29004e16d529073b6a5d0ba5626c0c96d0ddc1c9e07d8a649aeec050df9103"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "b4a39bc76748365f74a8943c483048dc9805e229"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "7df4756a208b4023cffffbf7bab12dbb"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/g/gcc-12/libgcc-s1_12.1.0-2ubuntu1~22.04_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "openssl",
      "SPDXID": "SPDXRef-apt2sbom.openssl",
      "versionInfo": "3.0.2-0ubuntu1.10",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "https://www.openssl.org/",
      "sourceInfo": "built package from: openssl 3.0.2-0ubuntu1.10",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "74fbef56da07706bbbb5e04c12f579d2c2b660e3e328aaab54a819adc004a6f6"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "5aeed416c1d92ac9afa6b3db0fa7432c262860db"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "dc1d240e082e1066ce5c2aba3b824102"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_3.0.2-0ubuntu1.10_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    },
    {
      "name": "libkrb5support0",
      "SPDXID": "SPDXRef-apt2sbom.libkrb5support0",
      "versionInfo": "1.19.2-2ubuntu0.2",
      "filesAnalyzed": false,
      "supplier": "Organization: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
      "homepage": "http://web.mit.edu/kerberos/",
      "sourceInfo": "built package from: libkrb5support0 1.19.2-2ubuntu0.2",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:deb/ubuntu/libkrb5support0@1.19.2-2ubuntu0.2?arch=amd64&distro=ubuntu-corrupt-string"
        }
      ],
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "c27700d3aafa1a0b2808d7b185d6a7bee989b494c1f7e870162611594f65fafe"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "5269eccefb798f64b8b388d0977a36bd0ead2183"
        },
        {
          "algorithm": "MD5",
          "checksumValue": "d706548f0b11f48ecbbf1c69c9ca729a"
        }
      ],
      "downloadLocation": "http://archive.ubuntu.com/ubuntu/pool/main/k/krb5/libkrb5support0_1.19.2-2ubuntu0.2_amd64.deb",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION"
    }
  ],
  "documentDescribes": [
    "SPDXRef-apt2sbom.libtirpc3",
    "SPDXRef-apt2sbom.libsystemd0",
    "SPDXRef-apt2sbom.libgcrypt20",
    "SPDXRef-apt2sbom.libkeyutils1",
    "SPDXRef-apt2sbom.libgssapi-krb5-2",
    "SPDXRef-apt2sbom.busybox-static",
    "SPDXRef-apt2sbom.libkrb5-3",
    "SPDXRef-apt2sbom.liblzma5",
    "SPDXRef-apt2sbom.libc6",
    "SPDXRef-apt2sbom.liblz4-1",
    "SPDXRef-apt2sbom.libcap2",
    "SPDXRef-apt2sbom.libssl3",
    "SPDXRef-apt2sbom.libk5crypto3",
    "SPDXRef-apt2sbom.libwrap0",
    "SPDXRef-apt2sbom.libgpg-error0",
    "SPDXRef-apt2sbom.libcom-err2",
    "SPDXRef-apt2sbom.ca-certificates",
    "SPDXRef-apt2sbom.libnsl2",
    "SPDXRef-apt2sbom.stunnel4",
    "SPDXRef-apt2sbom.libc6",
    "SPDXRef-apt2sbom.base-files",
    "SPDXRef-apt2sbom.base-files",
    "SPDXRef-apt2sbom.libzstd1",
    "SPDXRef-apt2sbom.libgcc-s1",
    "SPDXRef-apt2sbom.openssl",
    "SPDXRef-apt2sbom.libkrb5support0"
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-apt2sbom.libtirpc3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libtirpc3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgssapi-krb5-2"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libtirpc3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libtirpc-common"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libsystemd0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libsystemd0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libcap2"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libsystemd0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgcrypt20"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libsystemd0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.liblz4-1"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libsystemd0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.liblzma5"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libsystemd0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libzstd1"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgcrypt20",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgcrypt20",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgpg-error0"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkeyutils1",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgssapi-krb5-2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgssapi-krb5-2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libcom-err2"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgssapi-krb5-2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libk5crypto3"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgssapi-krb5-2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkrb5-3"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgssapi-krb5-2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkrb5support0"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkrb5-3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkrb5-3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libcom-err2"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkrb5-3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libk5crypto3"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkrb5-3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkeyutils1"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkrb5-3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkrb5support0"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkrb5-3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libssl3"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.liblzma5",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libc6",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgcc-s1"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libc6",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libcrypt1"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.liblz4-1",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libcap2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libssl3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libssl3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.debconf"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libk5crypto3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libk5crypto3",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkrb5support0"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libwrap0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libwrap0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libnsl2"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgpg-error0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libcom-err2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.ca-certificates",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.openssl"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.ca-certificates",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.debconf"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libnsl2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libnsl2",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libtirpc3"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libssl3"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libsystemd0"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libwrap0"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.init-system-helpers"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.systemd"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.perl:any"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.lsb-base"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.netbase"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.openssl"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.stunnel4",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.adduser"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.base-files",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.base-files",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libcrypt1"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.base-files",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.awk"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libzstd1",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgcc-s1",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.gcc-12-base"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libgcc-s1",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.openssl",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.openssl",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libssl3"
    },
    {
      "spdxElementId": "SPDXRef-apt2sbom.libkrb5support0",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-ContainerImage-XYZ",
      "relationshipType": "DESCRIBES"
    },
    {
      "spdxElementId": "SPDXRef-ContainerImage-XYZ",
      "relatedSpdxElement": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libtirpc3"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libsystemd0"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgcrypt20"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkeyutils1"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgssapi-krb5-2"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkrb5-3"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.liblzma5"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libc6"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.liblz4-1"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libcap2"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libssl3"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libk5crypto3"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libwrap0"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgpg-error0"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libcom-err2"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.ca-certificates"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libnsl2"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.stunnel4"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.base-files"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libzstd1"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libgcc-s1"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.openssl"
    },
    {
      "spdxElementId": "SPDXRef-OperatingSystem-XYZ",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-apt2sbom.libkrb5support0"
    }
  ]
}
```


#### References

- https://github.com/sbomtools/apt2sbom

- https://github.com/valentincanonical/chisel/blob/examples/examples/chiselled-ssl-base.dockerfile

- https://github.com/ubuntu-rocks/chiselled-jre/tree/channels/8/edge/chiselled-jre
