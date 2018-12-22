# AT&T DMD5620 Core

[![Build Status](https://travis-ci.org/sethm/dmd_core.svg?branch=master)](https://travis-ci.org/sethm/dmd_core)

Core logic for an AT&T / Teletype DMD 5620 terminal emulator

## Description

The AT&T / Teletype DMD 5620 terminal was a portrait display,
programmable, windowing terminal produced in the early 1980s. It came
out of research pioneered by Rob Pike and Bart Locanthi Jr., of AT&T
Bell Labs.

![DMD 5620 Terminal](https://static.loomcom.com/3b2/5620/dmd5620.jpg)

This project implements the core logic needed to emulate a DMD 5620
terminal, including:

- ROM
- RAM
- WE32100 CPU
- I/O

Note that there is no user interface: This is a back-end library only.
It may be used as a component to build a fully-fledged emulator,
however.

## Changelog

0.5.0: Non-breaking but major change. `dmd_core` now presents a
       C compatible API to make interacting with C and C++ code
       easier, without needed to write a full stub library.

0.4.0: Breaking change. TX to the keyboard from the terminal is
       now supported, so that clients can use it to detect when
       a bell (^G) request has been sent.

0.3.1: Added exception handling for memory errors, and a `run` function
       to free-run the CPU for a given number of steps.

0.3.0: Breaking change. Charater RX from RS-232 and keyboard are now
       handled by internal queues, and no longer return `DuartError`
       on failure.

0.2.1: Initial release.

## Emulator Reference Implementation

For a reference implementation emulator that uses this library,
please see the ["DMD" project on GitHub](https://github.com/sethm/dmd).
