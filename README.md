# Frabs Attack Check

Is your Linux server under attack right now? Get a command with your own code at **https://attack.frabs.net**, run it on the server, and the page shows the answer in about a minute: what kind of attack, where it comes from and what it's hitting.

```sh
curl -sL https://raw.githubusercontent.com/frabsnet/attack-check/main/run.sh | sudo sh -s YOURCODE
```

No curl? Use `wget -qO- … | sudo sh -s YOURCODE`.

## What it does

For 60 seconds it reads the network interface's packet and byte counters and the kernel's TCP, UDP and ICMP counters, every two seconds. Then it counts connections by state, by remote address and by local port, reads the connection-tracking table (with sudo), and lists the listening ports with the name of the program on each.

## What it never does

- It changes no setting, installs nothing and opens no port.
- It never sends this server's hostname or its own addresses, packet contents, file contents or command lines.
- Its temporary files are deleted when it finishes, or if you stop it.

It runs on any Linux with `/bin/sh`, `awk` and `curl` or `wget`. `ss` (from iproute2) adds the connection counts.

## License

Apache 2.0. Made by [Frabs](https://frabs.net), network protection for servers, hosting and game servers.
