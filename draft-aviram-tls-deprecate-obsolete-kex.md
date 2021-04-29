---
title: Deprecating Obsolete Key Exchange Methods in TLS
abbrev: Deprecating RSA and FFDH(E)
docname: draft-aviram-tls-deprecate-obsolete-kex-latest
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
  ICA:
    title: "Practical invalid curve attacks on TLS-ECDH"
    target: https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.704.7932&rep=rep1&type=pdf
    date: 2015-09-21
    author:
      - ins: T. Jager
      - ins: J. Schwenk
      - ins: J. Somorovsky

author:
 -
       ins: N. Aviram
       name: Nimrod Aviram
       organization:
       email: nimrod.aviram@gmail.com

 -
       ins: C. Bartle
       name: Carrick Bartle
       organization: Apple, Inc.
       email: cbartle@apple.com

--- abstract

This document deprecates the use of RSA key exchange in TLS, and limits the use
of Diffie Hellman key exchange over a finite field such as to avoid known
vulnerabilities or improper security properties.

--- middle

# Introduction

TLS supports a variety of key exchange algorithms, including RSA and Diffie Hellman
over a finite field, as well as elliptic curve Diffie Hellman (ECDH).
Diffie Hellman key exchange, over any group, may use either long-lived or ephemeral
secrets. Diffie Hellman key exchange with long-lived secrets over a finite field is
already deprecated in deprecate-ffdh (TODO cite properly).
This document focuses on Diffie Hellman over a finite field with ephemeral secrets
(FFDHE), as well as RSA key exchange.

Recent years have brought to light several security concerns
regarding FFDHE key exchange that stem from implementation choices.
Additionally, RSA key exchange suffers from security problems that are
independent of implementation choices, as well as problems that stem purely from
the difficulty of implementing countermeasures correctly.

At a rough glance, the problems affecting FFDHE are as follows (TODO add citations to everything here):

1. FFDHE suffers from interoperability problems, because there is no mechanism for negotiating the group size, and some implementations only support small group sizes.

2. In practice, operators use 1024 bit FFDHE groups, since this is the maximum
size that is widely supported. This leaves only a small security margin vs. the
current discrete log record, which stands at 795 bits.

3. Expanding on the previous point, a handful of very large computations would allow cheaply decrypting a relatively large fraction of FFDHE traffic.

4. When secrets are not fully ephemeral, FFDHE suffers from the {{Raccoon}} side channel attack.

5. FFDHE groups may have small subgroups, which may enable several attacks.

And the problems affecting RSA key exchange are as follows (should add citations to everything here):

1. RSA key exchange offers no forward secrecy, by construction.

2. RSA key exchange may be vulnerable to Bleichenbacher's attack. Experience
shows that variants of this attack arise every few years, because implementing the relevant countermeasure correctly is difficult.

3. In addition to the above point, there is no convenient mechanism in TLS for domain separation of keys. Therefore, a single endpoint that is vulnerable to Bleichenbacher's attack would affect all endpoints sharing the same RSA key.

I guess the plan is to elaborate on each point in a full paragraph in the
security considerations section?

Given these problems, this document updates {{!RFC4346}}, {{!RFC5246}}, {{!RFC4162}},
{{!RFC6347}}, {{!RFC5932}}, {{!RFC5288}}, {{!RFC6209}}, {{!RFC6367}}, {{!RFC8422}},
{{!RFC5289}}, and {{!RFC5469}} to deprecate RSA key exchange in TLS, and limit use of FFDH such that it provides acceptable security properties.

## Requirements

{::boilerplate bcp14}

# RSA {#rsa}

Clients and servers MUST NOT offer RSA cipher suites in TLS 1.0, 1.1, and 1.2
connections. This includes all cipher suites listed in the following table.

TODO fix this

| Ciphersuite  | Reference |
|:-|:-|
| TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |

# Ephemeral Diffie Hellman {#dhe}

Clients and servers MAY offer fully ephemeral FFDHE cipher suites in TLS 1.0,
1.1, and 1.2 connections, under the following conditions:

1. The secret DH key is fully ephemeral, that is a fresh DH exponent is generated for each TLS connection.
Note that this requirement is also specified in deprecate-ffdh.

2. The group is one of the following well-known groups described in {{!RFC7919}}:
ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192.

This applies to all cipher suites listed in the following table.

TODO FIX

| Ciphersuite  | Reference |
|:-|:-|
| TLS_ECDH_ECDSA_WITH_NULL_SHA | {{!RFC8422}} |

Note that FFDH cipher suites are already deprecated in deprecate-ffdh.

# IANA Considerations

This document makes no requests to IANA. All cipher suites listed in {{non-ephemeral}}
are already marked as not recommended in the "TLS Cipher Suites" registry.

# Security Considerations {#sec-considerations}

TODO

# Acknowledgments

TODO
This document was inspired by discussion on the TLS WG mailing list and
a suggestion by Filippo Valsorda following the release of the {{Raccoon}} attack. Thanks
to Christopher A. Wood for writing up the initial draft of this document.
