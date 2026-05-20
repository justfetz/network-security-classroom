---
slug: handshake
title: What Is a TCP Handshake?
summary: Learn how two systems agree to talk before application data moves.
---
A TCP handshake is the opening agreement between two systems before a reliable connection starts. The common shorthand is SYN, SYN-ACK, ACK.

That sequence matters because it tells you a lot. If you get a SYN-ACK back, something is listening. If you get a reset, the path may be open but nothing is listening on that port. If you get silence, a firewall or filter may be dropping the traffic.

Security engineers use handshake behavior to reason about exposure, filtering, and service state.
