# swampd

Early preview! swampd is an experimental daemon that embeds the Swamp scripting VM, exposes a
minimal UDP interface, and provides a simple key–value storage layer. It’s in its infancy, so don’t
expect a lot of bells and whistles - yet. In future releases, `swampd` will become a fully featured
package combining:

- Embedded Swamp scripting: compile and run Swamp scripts on the fly
- Network interface: lightweight UDP-based RPC to your scripts
- Simple storage: a key–value store (sled?) for persistent state
