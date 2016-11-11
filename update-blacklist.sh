#!/bin/bash

trap 'rm -rf "$MYTMPDIR"' EXIT

# usage update-blacklist.sh <configuration file>
# eg: update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf
if [[ -z "$1" ]]; then
    echo "Error: please specify a configuration file, e.g. $0 /etc/ipset-blacklist/ipset-blacklist.conf"
    exit 1
fi

if ! source "$1"; then
    echo "Error: can't load configuration file $1"
    exit 1
fi

VERBOSE=${VERBOSE:-no}

for CMD in curl egrep grep sed sort wc; do
	if ! which $CMD &> /dev/null; then
		echo >&2 "Error: searching PATH fails to find executable: $CMD"
		exit 1
	fi
done

if [[ ! -d $(dirname "$IP_BLACKLIST") || ! -d $(dirname "$IP_BLACKLIST_RESTORE") ]]; then
    echo >&2 "Error: missing directory(s): $(dirname "$IP_BLACKLIST" "$IP_BLACKLIST_RESTORE"|sort -u)"
    exit 1
fi

MYTMPDIR=$(mktemp -d)

# remote lists
if [[ ! -e "$IP_BLACKLIST_REMOTE" ]]; then
	touch "$IP_BLACKLIST_REMOTE"
	IP_BLACKLIST_TMP="$MYTMPDIR/ip_blacklist_tmp"
	CURL_ERROR=false
	for i in "${BLACKLISTS[@]}"
	do
		IP_TMP="$MYTMPDIR/ip_tmp"
		let HTTP_RC=`curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o $IP_TMP -s -w "%{http_code}" "$i"`
		if (( $HTTP_RC == 200 || $HTTP_RC == 302 || $HTTP_RC == 0 )); then # "0" because file:/// returns 000
			command grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' "$IP_TMP" >> "$IP_BLACKLIST_TMP"
		[[ "$VERBOSE" == yes ]] && echo "Adding IPs from $i"
		else
			CURL_ERROR=true
			echo >&2 -e "\nWarning: curl returned HTTP response code $HTTP_RC for URL $i"
		fi
		rm -f "$IP_TMP"
	done

	if [[ "${CURL_ERROR}" = true && ${IGNORE_CURL_ERRORS:-yes} == no ]]; then
		echo >&2 -e "\nError: curl returned an HTTP error code. Please fix or set IGNORE_CURL_ERRORS to yes"
		exit 1
	fi

	# sort -nu does not work as expected
	sed -r -e '/^(10\.|127\.|172\.16\.|192\.168\.)/d' "$IP_BLACKLIST_TMP"|sort -n|sort -mu >| "$IP_BLACKLIST_REMOTE"
	rm -f "$IP_BLACKLIST_TMP"
fi

# local black lists
if [[ ! -e "$IP_BLACKLIST_LOCAL" ]]; then
	touch "$IP_BLACKLIST_LOCAL"
	IP_BLACKLIST_LOCAL_TMP="$MYTMPDIR/ip_blacklist_local_tmp"
	for i in "${BLACKLISTS_LOCAL[@]}"
	do
		FILE="$IP_BLACKLIST_DIR/$i"
		if [[ -e "$FILE" ]]; then
			[[ "$VERBOSE" == yes ]] && echo "Blacklisting IPs from $FILE"
			grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' "$FILE" >> "$IP_BLACKLIST_LOCAL_TMP"
		else
			echo >&2 -e "\nError: BLACKLIST_LOCAL: no such file: $FILE"
			exit 1
		fi
	done
	sed -r -e '/^(10\.|127\.|172\.16\.|192\.168\.)/d' "$IP_BLACKLIST_LOCAL_TMP"|sort -n|sort -mu >| "$IP_BLACKLIST_LOCAL"
	rm -f "$IP_BLACKLIST_LOCAL_TMP"
fi

# sort -nu does not work as expected
cat "$IP_BLACKLIST_REMOTE" "$IP_BLACKLIST_LOCAL" | sed -r -e '/^(10\.|127\.|172\.16\.|192\.168\.)/d'|sort -V|sort -mu >| "$IP_BLACKLIST"

# local white lists
if [[ ! -e "$IP_WHITELIST_LOCAL" ]]; then
	touch "$IP_WHITELIST_LOCAL"
	IP_WHITELIST_LOCAL_TMP="$MYTMPDIR/ip_whitelist_local_tmp"
	for i in "${WHITELISTS_LOCAL[@]}"
	do
		FILE="$IP_BLACKLIST_DIR/$i"
		if [[ -e "$FILE" ]]; then
			[[ "$VERBOSE" == yes ]] && echo "Whitelisting IPs from $FILE"
			grep -Po '(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' "$FILE" >> "$IP_WHITELIST_LOCAL_TMP"
		else
			echo >&2 -e "\nError: WHITELIST_LOCAL: no such file: $FILE"
			exit 1
		fi
	done
	sort -V "$IP_WHITELIST_LOCAL_TMP"|sort -n|sort -mu >| "$IP_WHITELIST_LOCAL"
	rm -f "$IP_WHITELIST_LOCAL_TMP"
fi

IP_WHITELIST="$IP_WHITELIST_LOCAL"

# family = inet for IPv4 only
IPSET_BLACKLIST_OPTIONS="-exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}"
IPSET_BLACKLIST_CREATE="create $IPSET_BLACKLIST_NAME $IPSET_BLACKLIST_OPTIONS"
IPSET_TMP_BLACKLIST_CREATE="create $IPSET_TMP_BLACKLIST_NAME $IPSET_BLACKLIST_OPTIONS"
cat >| "$IP_BLACKLIST_RESTORE" <<EOF
$IPSET_TMP_BLACKLIST_CREATE
$IPSET_BLACKLIST_CREATE
flush $IPSET_TMP_BLACKLIST_NAME
add $IPSET_TMP_BLACKLIST_NAME 10.0.0.0/8 nomatch
add $IPSET_TMP_BLACKLIST_NAME 127.0.0.0/8 nomatch
add $IPSET_TMP_BLACKLIST_NAME 172.16.0.0/12 nomatch
add $IPSET_TMP_BLACKLIST_NAME 192.168.0.0/16 nomatch
EOF

sed -rn -e '/^#|^$/d' \
    -e "s/^([0-9./]+).*/add $IPSET_TMP_BLACKLIST_NAME \1 nomatch/p" "$IP_WHITELIST" >> "$IP_BLACKLIST_RESTORE"

# can be IPv4 including netmask notation
# IPv6 ? -e "s/^([0-9a-f:./]+).*/add $IPSET_TMP_BLACKLIST_NAME \1/p" \ IPv6
sed -rn -e '/^#|^$/d' \
    -e "s/^([0-9./]+).*/add $IPSET_TMP_BLACKLIST_NAME \1/p" "$IP_BLACKLIST" >> "$IP_BLACKLIST_RESTORE"

cat >> "$IP_BLACKLIST_RESTORE" <<EOF
swap $IPSET_BLACKLIST_NAME $IPSET_TMP_BLACKLIST_NAME
destroy $IPSET_TMP_BLACKLIST_NAME
EOF

if [[ "$VERBOSE" == yes ]]; then
    echo
    echo "Number of blacklisted IP/networks found: `wc -l $IP_BLACKLIST | cut -d' ' -f1`"
fi

# create set script
cat > "$IP_BLACKLIST_DIR/ip-blacklist.set.sh" <<EOSCRIPT
#!/bin/bash

for CMD in ipset iptables; do
	if ! which \$CMD &> /dev/null; then
		echo >&2 "Error: searching PATH fails to find executable: \$CMD"
		exit 1
	fi
done

if ! ipset list -n|command grep -q "$IPSET_BLACKLIST_NAME"; then
	if ! ipset $IPSET_BLACKLIST_CREATE; then
		echo >&2 "Error: while creating the initial ipset"
		exit 1
	fi
fi

if ! iptables -vL INPUT|command grep -q "match-set $IPSET_BLACKLIST_NAME"; then
	if ! iptables -I INPUT "${IPTABLES_IPSET_RULE_NUMBER:-1}" -m set --match-set "$IPSET_BLACKLIST_NAME" src -j DROP; then
		echo >&2 "Error: while adding the --match-set ipset rule to iptables"
		exit 1
	fi
fi

if ! ipset -file "$IP_BLACKLIST_RESTORE" restore; then
	echo >&2 "Error: while restoring ipset to iptables"
	exit 1
fi
EOSCRIPT
chmod +x "$IP_BLACKLIST_DIR/ip-blacklist.set.sh"

# create unset script
cat > "$IP_BLACKLIST_DIR/ip-blacklist.unset.sh" <<EOSCRIPT
#!/bin/bash
for CMD in ipset iptables; do
	if ! which \$CMD &> /dev/null; then
		echo >&2 "Error: searching PATH fails to find executable: \$CMD"
		exit 1
	fi
done

if iptables -vL INPUT|command grep -q "match-set $IPSET_BLACKLIST_NAME"; then
	if ! iptables -D INPUT -m set --match-set "$IPSET_BLACKLIST_NAME" src -j DROP; then
		echo >&2 "Error: while removing the --match-set $IPSET_BLACKLIST_NAME ipset rule from iptables"
		exit 1
	fi
fi

for IPSET in "$IPSET_BLACKLIST_NAME" "$IPSET_TMP_BLACKLIST_NAME"; do
	if ipset list -n|command grep -q "\$IPSET"; then
		if ! ipset destroy "\$IPSET"; then
			echo >&2 "Error: while destroying ipset \$IPSET"
			exit 1
		fi
	fi
done
EOSCRIPT
chmod +x "$IP_BLACKLIST_DIR/ip-blacklist.unset.sh"
