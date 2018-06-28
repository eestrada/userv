userv
=====

A simple Python daemonizer class for writing services with start/stop/status
features. I wrote it long ago, but never released it into the wild before now.
I'm keeping it as unencumbered as possible by releasing it into the public
domain using the UNLICENSE. Use it for whatever you want, however you want.

## Rationale

I found there were a number of other daemonizing classes, none of which fully
met my needs. Many did daemonization just fine, but had none of the other
features of a service (i.e. stop, restart, and status features). Some did the
other features, but were so high level that they lacked all ability to
customize the user interface of the service tools; they assumed you had created
a certain type of CLI. I made this library to be a "Goldilocks" type of
library: not too low-level, not too high-level, but the level of abstraction
that was "just right." Perhaps you disagree. Try it out and let me know what
you think.
