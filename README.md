# AT&T DMD5620 Core

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

This project is written in Rust, and uses [Neon Bindings](https://github.com/neon-bindings/neon)
to compile down to a Node.js library for later inclusion in an Electron
JavaScript application that will present the user interface and display
drawing area.
