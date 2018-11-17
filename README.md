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

## License

Copyright 2018, Seth J. Morabito <web@loomcom.com>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
