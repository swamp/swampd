# swampd

> pronounced "Swamped"

Early preview! swampd is an experimental daemon that embeds the Swamp scripting VM, exposes a
minimal UDP interface, and provides a simple key–value storage layer. It’s in its infancy, so don’t
expect a lot of bells and whistles - yet. In future releases, `swampd` will become a fully featured
package combining:

- Embedded Swamp scripting: compile and run Swamp scripts on the fly
- Network interface: lightweight UDP-based RPC to your scripts
- Simple storage: a key–value store (keydb) for persistent state

## Install DB

```sh
brew install keydb
```

- Configure persistence (in `/opt/homebrew/etc/keydb.conf`):

```text
save 60 1000
appendonly yes
appendfsync everysec
```

- Start it up

```sh
keydb-server /opt/homebrew/etc/keydb.conf
```

or

```sh
brew services start keydb
```

- Connect & inspect

```sh
keydb-cli ping        # -> PONG
keydb-cli set foo bar # -> OK
keydb-cli get foo     # -> "bar"
```

## Server

```sh
sudo useradd -m -s /bin/bash [name]
sudo usermod -aG sudo [name]
sudo passwd [name]
```

## Keydb

```sh
echo "deb https://download.keydb.dev/open-source-dist jammy main" | sudo tee /etc/apt/sources.list.d/keydb.list
sudo wget -O /etc/apt/trusted.gpg.d/keydb.gpg https://download.keydb.dev/open-source-dist/keyring.gpg

sudo apt update
sudo apt install keydb
```

### Keydb Service

```sh
sudo systemctl start keydb-server
sudo systemctl enable keydb-server
sudo systemctl status keydb-server

sudo journalctl -u keydb-server -f
```

### Download swampd

```sh
wget https://github.com/swamp/swampd/releases/download/v0.0.4/swampd-linux-x86_64.tar.gz
tar xvf swampd-linux-x86_64.tar.gz
./swampd
```

### swampd Service

```sh
/etc/systemd/system/swampd.service
```

```sh
sudo groupadd --system swampd
sudo useradd --system --gid swampd  --home /opt/swampd  --shell /usr/sbin/nologin --comment "SwampD service account" swampd
sudo chown -R swampd:swampd /opt/swampd
sudo chown -R swampd:swampd /etc/swampd

```

```sh
sudo systemctl daemon-reload
sudo systemctl enable swampd
sudo systemctl start swampd

sudo systemctl status swampd
sudo journalctl -u swampd -f
```

### Copy server script files to cloud

```sh
rsync -avL -e ssh --rsync-path="sudo rsync" server packages swamp.yini username@game.swampd.net:/etc/game/
```
