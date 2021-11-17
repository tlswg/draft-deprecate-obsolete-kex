---
title: Deprecating Obsolete Key Exchange Methods in TLS
abbrev: Deprecating RSA and FFDH(E)
docname: draft-bartle-tls-deprecate-obsolete-kex-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

informative:
  Raccoon:
    title: "Raccoon Attack: Finding and Exploiting Most-Significant-Bit-Oracles in TLS-DH(E)"
    target: https://raccoon-attack.com/RacoonAttack.pdf
    date: 2020-09-09
    author:
      - ins: R. Merget
      - ins: M. Brinkmann
      - ins: N. Aviram
      - ins: J. Somorovsky
      - ins: J. Mittmann
      - ins: J. Schwenk
  deprecate-ffdh:
    title: "Deprecating FFDH Ciphersuites in TLS"
    target: https://datatracker.ietf.org/doc/draft-bartle-tls-deprecate-ffdhe/
    date: 2021-06
    author:
      - ins: C. Bartle
      - ins: N. Aviram
      - ins: F. Valsorda
  weak-dh:
    title: "Weak Diffie-Hellman and the Logjam Attack"
    target: https://weakdh.org/
    date: 2015-10
    author:
      - ins: D. Adrian
      - ins: K. Bhargavan
      - ins: Z. Durumeric
      - ins: P. Gaudry
      - ins: M. Green
      - ins: J. A. Halderman
      - ins: N. Heninger
      - ins: D. Springall
      - ins: E. Thomé
      - ins: L. Valenta
      - ins: B. VanderSloot
      - ins: E. Wustrow
      - ins: S. Zanella-Béguelin
      - ins: P. Zimmermann
  subgroups:
    title: "Measuring small subgroup attacks against Diffie-Hellman"
    target: https://eprint.iacr.org/2016/995/20161017:193515
    date: 2016-10-15
    author:
      - ins: L. Valenta
      - ins: D. Adrian
      - ins: A. Sanso
      - ins: S. Cohney
      - ins: J. Fried
      - ins: M. Hastings
      - ins: J. A. Halderman
      - ins: N. Heninger
  BLEI:
    title: "Chosen Ciphertext Attacks against Protocols Based on RSA
    Encryption Standard PKCS #1"
    author:
      - ins: D. Bleichenbacher
    seriesinfo: "Advances in Cryptology -- CRYPTO'98, LNCS vol. 1462, pages:
    1-12"
    date: 1998
  ROBOT:
    title: "Return Of Bleichenbacher's Oracle Threat (ROBOT)"
    author:
      - ins: H. Boeck
      - ins: J. Somorovsky
      - ins: C. Young
    seriesinfo: "27th USENIX Security Symposium"
    date: 2018
  NEW-BLEI:
    title: "Revisiting SSL/TLS Implementations: New Bleichenbacher Side Channels and Attacks"
    target: https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-meyer.pdf
    date: 2014-08
    author:
      - ins: C. Meyer
      - ins: J. Somorovsky
      - ins: E. Weiss
      - ins: J. Schwenk
      - ins: S. Schinzel
      - ins: E. Tews
  DROWN:
    title: "DROWN: Breaking TLS using SSLv2"
    target: https://drownattack.com/drown-attack-paper.pdf
    date: 2016-08
    author:
      - ins: N. Aviram
      - ins: S. Schinzel
      - ins: J. Somorovsky
      - ins: N. Heninger
      - ins: M. Dankel
      - ins: J. Steube
      - ins: L. Valenta
      - ins: D. Adrian
      - ins: J. A. Halderman
      - ins: V. Dukhovni
      - ins: E. Käsper
      - ins: S. Cohney
      - ins: S. Engels
      - ins: C. Paar
      - ins: Y. Shavitt
  XPROT:
    title: "On the Security of TLS 1.3 and QUIC Against Weaknesses in PKCS#1 v1.5 Encryption"
    author:
      - ins: T. Jager
      - ins: J. Schwenk
      - ins: J. Somorovsky
    seriesinfo: Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security
    date: 2015
  SC-tls-des-idea-ciphers-to-historic:
    title: "Moving single-DES and IDEA TLS ciphersuites to Historic"
    target: https://datatracker.ietf.org/doc/status-change-tls-des-idea-ciphers-to-historic/
    author:
      -ins: Benjamin Kaduk
    date: 2021-01-25
  DLOG795:
    title: "Comparing the difficulty of factorization and discrete logarithm: a 240-digit experiment"
    target: https://eprint.iacr.org/2020/697
    author:
      - ins: F. Boudot
      - ins: P. Gaudry
      - ins: A. Guillevic
      - ins: N. Heninger
      - ins: E. Thomé
      - ins: P. Zimmermann
    date: 2020-08-17
  server_side_tls:
    title: "Server Side TLS"
    target: https://wiki.mozilla.org/Security/Server_Side_TLS
    author:
      - ins: A. King
    date: 2020-07
author:
-
      ins: C. Bartle
      name: Carrick Bartle
      organization: Apple, Inc.
      email: cbartle@apple.com
 -
       ins: N. Aviram
       name: Nimrod Aviram
       organization:
       email: nimrod.aviram@gmail.com

--- abstract

This document deprecates the use of RSA key exchange in TLS, limits the use
of Diffie Hellman key exchange over a finite field, and  discourages the use of
elliptic curve Diffie Hellman cipher suites, such as to avoid known
vulnerabilities or improper security properties.

--- middle

# Introduction

TLS supports a variety of key exchange algorithms, including RSA and Diffie Hellman
over a finite field, as well as elliptic curve Diffie Hellman (ECDH).

Diffie Hellman key exchange, over any group, comes in ephemeral and
non-ephemeral varieties. Non-ephemeral DH algorithms use static DH public keys
included in the authenticating peer's certificate; see {{?RFC4492}} for discussion.
In contrast, ephemeral DH algorithms use ephemeral DH public keys sent in the
handshake and authenticated by the peer's certificate. Ephemeral and
non-ephemeral finite field DH algorithms are called DHE and DH, respectively,
and ephemeral and non-ephemeral elliptic curve DH algorithms are called ECDHE
and ECDH, respectively {{?RFC4492}}.

In general, non-ephemeral cipher suites are not recommended due to their lack of forward secrecy. However, as demonstrated by the {{Raccoon}} attack on finite-field DH, public key reuse, either via non-ephemeral cipher suites or reused keys with ephemeral cipher suites, can lead to timing side channels that may leak connection secrets. For elliptic curve DH, invalid curve attacks similarly exploit secret reuse in order to break security {{ICA}}, further demonstrating the risk of reusing public keys. While both side channels can be avoided in implementations, experience shows that in practice, implementations may fail to thwart such attacks due to the complexity of the required mitigations.

Additionally, RSA key exchange suffers from security problems that are independent of implementation choices, as well as problems that stem purely from the difficulty of implementing security countermeasures correctly.

At a rough glance, the problems affecting FFDHE are as follows:

1. FFDHE suffers from interoperability problems, because there is no mechanism for negotiating the group size, and some implementations only support small group sizes; see {{!RFC7919}}, Section 1.

2. In practice, some operators use 1024 bit FFDHE groups, since this is the
maximum size that ensures wide support; see {{!RFC7919}}, Section 1.
This size leaves only a small security margin vs. the current discrete log record, which stands at 795 bits {{DLOG795}}.

3. Expanding on the previous point, a handful of very large computations would allow cheaply decrypting a relatively large fraction of FFDHE traffic
{{weak-dh}}.

4. When secrets are not fully ephemeral, FFDHE suffers from the {{Raccoon}} side channel attack. Note that FFDH is inherently vulnerable to the Raccoon attack, unless constant-time mitigations are employed.

5. FFDHE groups may have small subgroups, which may enable several attacks
{{subgroups}}.

And the problems affecting RSA key exchange are as follows:

1. RSA key exchange offers no forward secrecy, by construction.

2. RSA key exchange may be vulnerable to Bleichenbacher's attack {{BLEI}}.
Experience shows that variants of this attack arise every few years, because
implementing the relevant countermeasure correctly is difficult; see
{{ROBOT}}, {{NEW-BLEI}}, {{DROWN}}.

3. In addition to the above point, there is no convenient mechanism in TLS for domain separation of keys. Therefore, a single endpoint that is vulnerable to Bleichenbacher's attack would affect all endpoints sharing the same RSA key; see
{{XPROT}}, {{DROWN}}.

Given these problems, this document updates {{!RFC4346}}, {{!RFC5246}}, {{!RFC4162}}, {{!RFC6347}}, {{!RFC5932}}, {{!RFC5288}}, {{!RFC6209}}, {{!RFC6367}}, {{!RFC8422}}, {{!RFC5289}}, and {{!RFC5469}} to deprecate cipher suites with key reuse, prohibiting and discouraging their use.
## Requirements

{::boilerplate bcp14}

# Non-Ephemeral Diffie Hellman {#non-ephemeral}

Clients MUST NOT offer non-ephemeral DH cipher suites in TLS 1.2 connections. (Note that
TLS 1.0 and 1.1 are deprecated by {{!RFC8996}}.) This includes all cipher suites listed
in the following table.

| Ciphersuite  | Reference |
|:-|:-|
| TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DH_DSS_WITH_DES_CBC_SHA | {{!RFC5469}} |
| TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DH_RSA_WITH_DES_CBC_SHA | {{!RFC5469}} |
| TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 | {{!RFC4346}}{{RFC6347}} |
| TLS_DH_anon_WITH_RC4_128_MD5 | {{!RFC5246}}{{RFC6347}} |
| TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DH_anon_WITH_DES_CBC_SHA | {{!RFC5469}} |
| TLS_DH_anon_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DH_DSS_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DH_DSS_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DH_DSS_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DH_DSS_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DH_DSS_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DH_RSA_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DH_anon_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DH_RSA_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DH_RSA_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DH_DSS_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DH_DSS_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DH_anon_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DH_anon_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |

Clients SHOULD NOT offer non-ephemeral ECDH cipher suites in TLS 1.2
connections. (Note that TLS 1.0 and 1.1 are deprecated by {{!RFC8996}}.) This
includes all cipher suites listed in the following table.

| Ciphersuite  | Reference |
|:-|:-|
| TLS_ECDH_ECDSA_WITH_NULL_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_RC4_128_SHA | {{!RFC8422}}{{RFC6347}} |
| TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_NULL_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_RC4_128_SHA | {{!RFC8422}}{{RFC6347}} |
| TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_AES_128_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_AES_256_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_NULL_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_RC4_128_SHA | {{!RFC8422}}{{RFC6347}} |
| TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_AES_128_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_AES_256_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC6367}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 | {{!RFC6367}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |

# Ephemeral Finite Field Diffie Hellman {#dhe}

Clients and servers MAY offer fully ephemeral FFDHE cipher suites in TLS 1.2 connections (TLS 1.0 and 1.1 are deprecated by {{!RFC8996}}), under the following conditions:

1. Clients and servers MUST NOT reuse ephemeral DHE public keys across TLS connections for all existing (and future) TLS versions. Doing so invalidates forward secrecy properties of these connections. For DHE, such reuse may also lead to vulnerabilities such as those used in the {{Raccoon}} attack. See {{sec-considerations}} for related discussion.

2. The group is one of the following well-known groups described in {{!RFC7919}}:
ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192.

We note that previously, supporting the broadest range of clients would have required supporting either RSA key exchange, or 1024-bit FFDHE.
This is no longer the case, and it is possible to support most clients released
since circa 2015 using 2048-bit FFDHE, or more modern key exchange methods, and
without RSA key exchange {{server_side_tls}}.

The above requirements apply to all cipher suites listed in the following table.

| Ciphersuite  | Reference |
|:-|:-|
| TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DHE_DSS_WITH_DES_CBC_SHA | {{!RFC5469}}{{SC-tls-des-idea-ciphers-to-historic}} |
| TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DHE_RSA_WITH_DES_CBC_SHA | {{!RFC5469}}{{SC-tls-des-idea-ciphers-to-historic}} |
| TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DHE_PSK_WITH_NULL_SHA | {{!RFC4785}} |
| TLS_DHE_DSS_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DHE_RSA_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DHE_DSS_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DHE_RSA_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DHE_PSK_WITH_RC4_128_SHA | {{!RFC4279}}{{!RFC6347}} |
| TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA | {{!RFC4279}} |
| TLS_DHE_PSK_WITH_AES_128_CBC_SHA | {{!RFC4279}} |
| TLS_DHE_PSK_WITH_AES_256_CBC_SHA | {{!RFC4279}} |
| TLS_DHE_DSS_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DHE_RSA_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 | {{!RFC5487}} |
| TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 | {{!RFC5487}} |
| TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 | {{!RFC5487}} |
| TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 | {{!RFC5487}} |
| TLS_DHE_PSK_WITH_NULL_SHA256 | {{!RFC5487}} |
| TLS_DHE_PSK_WITH_NULL_SHA384 | {{!RFC5487}} |
| TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC6367}} |
| TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 | {{!RFC6367}} |
| TLS_DHE_RSA_WITH_AES_128_CCM | {{!RFC6655}} |
| TLS_DHE_RSA_WITH_AES_256_CCM | {{!RFC6655}} |
| TLS_DHE_RSA_WITH_AES_128_CCM_8 | {{!RFC6655}} |
| TLS_DHE_RSA_WITH_AES_256_CCM_8 | {{!RFC6655}} |
| TLS_DHE_PSK_WITH_AES_128_CCM | {{!RFC6655}} |
| TLS_DHE_PSK_WITH_AES_256_CCM | {{!RFC6655}} |
| TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | {{!RFC7905}} |
| TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 | {{!RFC7905}} |

# RSA {#rsa}

Clients and servers MUST NOT offer RSA cipher suites in TLS 1.2
connections. (Note that TLS 1.0 and 1.1 are deprecated by {{!RFC8996}}.). This includes all cipher suites listed in the following table.
Note that these cipher suites are already marked as not recommended in the "TLS
Cipher Suites" registry.

| Ciphersuite  | Reference |
|:-|:-|
| TLS_RSA_WITH_NULL_MD5 | {{!RFC5246}} |
| TLS_RSA_WITH_NULL_SHA | {{!RFC5246}} |
| TLS_RSA_EXPORT_WITH_RC4_40_MD5 | {{!RFC4346}}{{!RFC6347}} |
| TLS_RSA_WITH_RC4_128_MD5 | {{!RFC5246}}{{!RFC6347}} |
| TLS_RSA_WITH_RC4_128_SHA | {{!RFC5246}}{{!RFC6347}} |
| TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 | {{!RFC4346}} |
| TLS_RSA_WITH_IDEA_CBC_SHA | {{!RFC5469}}{{SC-tls-des-idea-ciphers-to-historic}} |
| TLS_RSA_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_RSA_WITH_DES_CBC_SHA | {{!RFC5469}}{{SC-tls-des-idea-ciphers-to-historic}} |
| TLS_RSA_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_RSA_PSK_WITH_NULL_SHA | {{!RFC4785}} |
| TLS_RSA_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_RSA_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_RSA_WITH_NULL_SHA256 | {{!RFC5246}} |
| TLS_RSA_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_RSA_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_RSA_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_RSA_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_RSA_PSK_WITH_RC4_128_SHA | {{!RFC4279}}{{!RFC6347}} |
| TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA | {{!RFC4279}} |
| TLS_RSA_PSK_WITH_AES_128_CBC_SHA | {{!RFC4279}} |
| TLS_RSA_PSK_WITH_AES_256_CBC_SHA | {{!RFC4279}} |
| TLS_RSA_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_RSA_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_RSA_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 | {{!RFC5487}} |
| TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 | {{!RFC5487}} |
| TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 | {{!RFC5487}} |
| TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 | {{!RFC5487}} |
| TLS_RSA_PSK_WITH_NULL_SHA256 | {{!RFC5487}} |
| TLS_RSA_PSK_WITH_NULL_SHA384 | {{!RFC5487}} |
| TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_RSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_RSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_RSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_RSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC6367}} |
| TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 | {{!RFC6367}} |
| TLS_RSA_WITH_AES_128_CCM | {{!RFC6655}} |
| TLS_RSA_WITH_AES_256_CCM | {{!RFC6655}} |
| TLS_RSA_WITH_AES_128_CCM_8 | {{!RFC6655}} |
| TLS_RSA_WITH_AES_256_CCM_8 | {{!RFC6655}} |
| TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 | {{!RFC7905}} |

# IANA Considerations

This document makes no requests to IANA. Note that all cipher suites listed in
{{rsa}} and in {{non-ephemeral}} are already marked as not recommended in the "TLS Cipher Suites"
registry.

# Security Considerations {#sec-considerations}

Non-ephemeral finite field DH cipher suites (TLS_DH_\*), as well as ephemeral key reuse
for finite field DH cipher suites, are prohibited due to the {{Raccoon}} attack. Both are
already considered bad practice since they do not provide forward secrecy. However,
Raccoon revealed that timing side channels in processing TLS premaster secrets may be
exploited to reveal the encrypted premaster secret.

For non-ephemeral elliptic curve DH cipher suites, invalid curve attacks similarly exploit secret reuse in order to break security. These attacks have been shown to be practical against real-world TLS
implementations {{ICA}}. Therefore, this document discourages the reuse of elliptic
curve DH public keys.
# Acknowledgments

This document was inspired by discussion on the TLS WG mailing list and
a suggestion by Filippo Valsorda following the release of the {{Raccoon}} attack.
Thanks to Christopher A. Wood for writing up the initial draft of this document.
