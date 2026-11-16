#!/bin/sh
# Frabs Attack Check for Linux: https://attack.frabs.net
#
# Watches this server's network for 60 seconds and shows on attack.frabs.net whether it is
# under attack right now, what kind, where from and what is being hit. Read-only: it
# changes no setting, installs nothing, and every file it makes goes in one temporary
# folder that is deleted when it finishes.
#
#   curl -sL https://raw.githubusercontent.com/frabsnet/attack-check/main/run.sh | sudo sh -s YOURCODE
#
# Without sudo it still runs, but the connection-tracking table and which program owns
# each port need root, so the report has less to go on.
#
# What it sends to attack.frabs.net: the network interface's packet and byte counters and
# the kernel's TCP, UDP and ICMP counters every two seconds; incoming connections counted
# by state, by local port and by remote address; the local ports that are listening and
# the name of the program on each. Never this server's hostname or its own addresses (its
# own connections out are left out), packet contents, file contents or command lines.

API="https://api.frabs.net/v1/tools/attack"
LC_ALL=C; export LC_ALL
PATH="$PATH:/usr/sbin:/sbin"

has() { command -v "$1" >/dev/null 2>&1; }
json() { printf '"%s"' "$(printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-190)"; }
post() {
  if [ "$HTTP" = curl ]; then curl -fsS -m 10 -X POST -H 'content-type: application/json' --data-binary "@$1" "$API/$CODE/event" </dev/null >/dev/null 2>&1
  else wget -q -T 10 -O /dev/null --header='content-type: application/json' --post-file="$1" "$API/$CODE/event" </dev/null >/dev/null 2>&1; fi
  return 0
}
send() { printf '%s' "$1" > "$WORK/msg.json"; post "$WORK/msg.json"; }
step() { send "{\"step\":\"$1\",\"state\":\"$2\",\"detail\":$(json "$3")}"; [ "$2" = running ] && printf '  %-36s ' "$3"; [ "$2" = done ] && echo "done"; return 0; }

# The kernel's counters, read once: interface bytes/packets/drops, then TCP, UDP and ICMP totals.
counters() {
  t=$(cut -d' ' -f1 /proc/uptime)
  dev=$(awk -v i="$IFACE:" '{ sub(/^ +/, ""); sub(/:/, ": ") } $1 == i { print $2, $3, $5, $10, $11 }' /proc/net/dev)
  set -- ${dev:-0 0 0 0 0}
  rb=$1; rp=$2; rd=$3; tb=$4; tp=$5
  kern=$(awk '$1 ~ /:$/ { if (!($1 in h)) { h[$1] = $0; next } n = split(h[$1], H); for (i = 2; i <= NF && i <= n; i++) v[$1 H[i]] = $i; delete h[$1] }
    END { printf "%s %s %s %s %s %s %s %s %s %s %s", v["Tcp:PassiveOpens"]+0, v["Tcp:InSegs"]+0, v["Tcp:AttemptFails"]+0, v["Udp:InDatagrams"]+0, v["Udp:NoPorts"]+0, v["Udp:InErrors"]+0, v["Udp:RcvbufErrors"]+0, v["Icmp:InMsgs"]+0, v["TcpExt:SyncookiesSent"]+0, v["TcpExt:ListenDrops"]+0, v["Tcp:InErrs"]+0 }' /proc/net/snmp /proc/net/netstat 2>/dev/null)
  set -- ${kern:-0 0 0 0 0 0 0 0 0 0 0}
  printf '{"t":%s,"rb":%s,"rp":%s,"rd":%s,"tb":%s,"tp":%s,"tpo":%s,"tis":%s,"taf":%s,"ui":%s,"unp":%s,"uie":%s,"urb":%s,"ii":%s,"sc":%s,"ld":%s,"tie":%s}' \
    "$t" "${rb:-0}" "${rp:-0}" "${rd:-0}" "${tb:-0}" "${tp:-0}" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}"
}

# "count key" lines to a JSON list of [key, count], keeping only addresses and port numbers.
pairs() { awk 'BEGIN { printf "[" } $2 ~ /^[0-9A-Fa-f:.|a-z]+$/ { printf "%s[\"%s\",%d]", (n++ ? "," : ""), $2, $1 } END { printf "]" }'; }
# The address part of an ss address ("1.2.3.4:80", "[2001:db8::1]:443", "::ffff:1.2.3.4:22").
peer() { awk '{ a = $0; sub(/:[0-9*]+$/, "", a); gsub(/[][]/, "", a); sub(/^::ffff:/, "", a); sub(/%.*/, "", a); print a }'; }
port() { awk '{ n = split($0, p, ":"); print p[n] }'; }

main() {
  CODE=$1
  case $CODE in
    [A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9][A-Z2-9]) ;;
    *) echo "Usage: curl -sL https://raw.githubusercontent.com/frabsnet/attack-check/main/run.sh | sudo sh -s YOURCODE"
       echo "Get your code at https://attack.frabs.net"; exit 1 ;;
  esac
  if has curl; then HTTP=curl; elif has wget; then HTTP=wget; else echo "This check needs curl or wget."; exit 1; fi
  if [ "$HTTP" = curl ]; then curl -fsS -m 15 -o /dev/null "$API/$CODE" </dev/null 2>/dev/null; else wget -q -T 15 -O /dev/null "$API/$CODE" </dev/null 2>/dev/null; fi
  if [ $? -ne 0 ]; then
    echo "This server can't reach https://api.frabs.net, so the check couldn't be shown."
    echo "Check the code is right and was made in the last two hours: https://attack.frabs.net"; exit 1
  fi
  [ -r /proc/net/dev ] || { echo "This check reads /proc/net, which this system doesn't have."; exit 1; }
  ROOT=no; [ "$(id -u)" = 0 ] && ROOT=yes
  WORK=$(mktemp -d 2>/dev/null || { d="/tmp/frabs-attack.$$"; mkdir "$d" && echo "$d"; })
  trap 'rm -rf "$WORK"' EXIT
  trap 'echo; echo "Stopped. Nothing was changed, and its temporary files are gone."; rm -rf "$WORK"; exit 130' INT TERM

  echo
  echo "  Frabs Attack Check · https://attack.frabs.net/$CODE"
  echo "  Read-only: nothing is changed or installed. Takes about 70 seconds."
  [ $ROOT = no ] && echo "  Not running as root: connection tracking is skipped. Add sudo for the full check."
  echo
  send "{\"state\":\"start\",\"platform\":\"linux\",\"root\":$( [ $ROOT = yes ] && echo true || echo false )}"

  # ---- the system and its main network interface
  step system running "Reading the system"
  IFACE=$(ip route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
  [ -n "$IFACE" ] || IFACE=$(awk -F: 'NR > 2 { gsub(/ /, "", $1); if ($1 != "lo") { print $1; exit } }' /proc/net/dev)
  os=$( (. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}") )
  virt=$(systemd-detect-virt 2>/dev/null || echo unknown)
  speed=$(cat "/sys/class/net/$IFACE/speed" 2>/dev/null || echo 0)
  case $speed in ''|*[!0-9]*) speed=0 ;; esac
  cores=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
  send "{\"system\":{\"os\":$(json "$os"),\"kernel\":$(json "$(uname -r)"),\"virtualisation\":$(json "$virt"),\"iface_mbit\":$speed,\"cores\":$cores}}"
  step system done "Reading the system"

  # ---- 60 seconds of counters, every two seconds, sent five at a time
  step watch running "Watching traffic for 60 seconds"
  i=0; batch=""
  while [ $i -le 30 ]; do
    c=$(counters); batch="${batch:+$batch,}$c"
    if [ $((i % 5)) -eq 0 ]; then send "{\"samples\":[$batch]}"; batch=""; fi
    i=$((i + 1)); [ $i -le 30 ] && sleep 2
  done
  [ -n "$batch" ] && send "{\"samples\":[$batch]}"
  step watch done "Watching traffic for 60 seconds"

  # ---- connections right now: by state, by remote address, by local port
  step connections running "Reading connections"
  # This server's own addresses, so its own connections out (to updates, APIs) are never counted as visitors,
  # and its addresses are never sent. Kept in the temporary folder only.
  { ip -o addr show 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }'; echo 127.0.0.1; echo ::1; } > "$WORK/self"
  if has ss; then
    ss -Htan 2>/dev/null > "$WORK/tcp"
    # Only connections coming in: those to a port this server listens on.
    awk '$1 == "LISTEN" { n = split($4, a, ":"); print a[n] }' "$WORK/tcp" | sort -u > "$WORK/lports"
    awk 'NR == FNR { l[$1] = 1; next } $1 != "LISTEN" { n = split($4, a, ":"); if (a[n] in l) print }' "$WORK/lports" "$WORK/tcp" > "$WORK/tcp_in"
    states=$(awk '{ print $1 }' "$WORK/tcp_in" | sort | uniq -c | awk 'BEGIN { printf "[" } { printf "%s[\"%s\",%d]", (n++ ? "," : ""), $2, $1 } END { printf "]" }')
    remotes=$(awk '{ print $5 }' "$WORK/tcp_in" | peer | awk 'NR == FNR { s[$1] = 1; next } !($1 in s)' "$WORK/self" - | sort | uniq -c | sort -rn | head -40 | pairs)
    synrecv=$(awk '$1 == "SYN-RECV" { print $5 }' "$WORK/tcp_in" | peer | sort | uniq -c | sort -rn | head -20 | pairs)
    synrecv_n=$(awk '$1 == "SYN-RECV"' "$WORK/tcp_in" | wc -l)
    lports=$(awk '{ print $4 }' "$WORK/tcp_in" | port | sort | uniq -c | sort -rn | head -20 | pairs)
    send "{\"tcp\":{\"states\":$states,\"remotes\":$remotes,\"synrecv\":$synrecv,\"synrecv_total\":$synrecv_n,\"local_ports\":$lports}}"
  fi
  # The connection-tracking table (root): flows by source, by destination port and by source port.
  ct=""
  if [ $ROOT = yes ]; then
    if [ -r /proc/net/nf_conntrack ]; then ct=/proc/net/nf_conntrack
    elif has conntrack; then conntrack -L 2>/dev/null > "$WORK/ct" && ct="$WORK/ct"; fi
  fi
  if [ -n "$ct" ]; then
    head -n 300000 "$ct" | awk '{ p = ""; s = ""; sp = ""; dp = ""
        for (i = 1; i <= NF; i++) {
          if (p == "" && ($i == "tcp" || $i == "udp" || $i == "icmp" || $i == "icmpv6")) p = $i
          if (s == "" && $i ~ /^src=/) s = substr($i, 5)
          if (sp == "" && $i ~ /^sport=/) sp = substr($i, 7)
          if (dp == "" && $i ~ /^dport=/) dp = substr($i, 7)
        }
        if (p == "") next
        print p, s, sp, dp }' | awk 'NR == FNR { self[$1] = 1; next } !($2 in self)' "$WORK/self" - > "$WORK/flows"
    total=$(wc -l < "$WORK/flows")
    by_src=$(awk '{ print $1 "|" $2 }' "$WORK/flows" | sort | uniq -c | sort -rn | head -40 | pairs)
    by_dport=$(awk '$4 != "" { print $1 "|" $4 }' "$WORK/flows" | sort | uniq -c | sort -rn | head -20 | pairs)
    by_sport=$(awk '$1 == "udp" && $3 != "" { print "udp|" $3 }' "$WORK/flows" | sort | uniq -c | sort -rn | head -15 | pairs)
    by_proto=$(awk '{ print $1 }' "$WORK/flows" | sort | uniq -c | pairs)
    distinct=$(awk '{ print $2 }' "$WORK/flows" | sort -u | wc -l)
    cmax=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
    send "{\"conntrack\":{\"total\":$total,\"max\":${cmax:-0},\"sources\":$distinct,\"by_proto\":$by_proto,\"by_source\":$by_src,\"by_dport\":$by_dport,\"by_udp_sport\":$by_sport}}"
  fi
  step connections done "Reading connections"

  # ---- what is listening, and which program (the name only)
  step services running "Reading listening services"
  if has ss; then
    ss -Hltunp 2>/dev/null | awk '{ n = split($5, a, ":"); prog = ""; if (match($0, /\("[^"]+"/)) prog = substr($0, RSTART + 2, RLENGTH - 3)
        gsub(/[^A-Za-z0-9._-]/, "", prog); print $1 "|" a[n] "|" prog }' | sort -u | head -60 > "$WORK/listen"
    list=$(awk -F'|' 'BEGIN { printf "[" } $2 ~ /^[0-9]+$/ { printf "%s[\"%s\",%s,\"%s\"]", (n++ ? "," : ""), $1, $2, $3 } END { printf "]" }' "$WORK/listen")
    send "{\"listening\":$list}"
  fi
  step services done "Reading listening services"

  step cleanup running "Removing its temporary files"
  rm -rf "$WORK"; mkdir -p "$WORK"
  step cleanup done "Removing its temporary files"
  send "{\"state\":\"finished\"}"
  echo
  echo "  Your result: https://attack.frabs.net/$CODE"
  echo
}

main "$@"
