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

## Emulator Reference Implementation

For a reference implementation emulator that uses this library,
please see the ["DMD" project on GitHub](https://github.com/sethm/dmd).
