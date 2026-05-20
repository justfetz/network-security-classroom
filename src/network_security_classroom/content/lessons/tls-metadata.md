---
slug: tls-metadata
title: TLS, Encryption, and Metadata
summary: Understand what TLS protects and what it still leaves visible to observers.
---
TLS is designed to protect the content of communication in transit. It helps keep passwords, page contents, tokens, and application data private from casual interception.

But TLS does not hide everything. Observers can often still see who is talking, when they talk, how often they talk, and other surrounding details such as DNS lookups, destination IPs, timing, and traffic volume.

That difference between content and metadata is one of the most important ideas in modern security. Encryption is powerful, but it is not the same thing as invisibility.
