#!/bin/bash

# REQUIRES:
# https://github.com/firehol/iprange
# Ubuntu: apt install iprange

trap 'rm -rf "$MYTMPDIR"' EXIT

# usage update-blacklist.sh <configuration file>
# eg: update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf
if [[ -z "$1" ]]; then
    echo "Error: please specify a configuration file, e.g. $0 /etc/ipset-blacklist/ipset-blacklist.conf"
    exit 1
fi

# shellcheck disable=SC1090
if ! source "$1"; then
    echo "Error: can't load configuration file $1"
    exit 1
fi

VERBOSE=${VERBOSE:-no}

for CMD in curl egrep grep sed sort wc iprange; do
	if ! which $CMD &> /dev/null; then
		echo >&2 "Error: searching PATH fails to find executable: $CMD"
		exit 1
	fi
done

if [[ ! -d $(dirname "$IP_BLACKLIST") || ! -d $(dirname "$IP_BLACKLIST_RESTORE") ]]; then
    echo >&2 "Error: missing directory(s): $(dirname "$IP_BLACKLIST" "$IP_BLACKLIST_RESTORE"|sort -u)"
    exit 1
fi

function filterIPv4() {
	grep -hPo '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2})?$' "$@" \
	|sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)/\1.\2.\3.\4/' \
	|iprange
}


MYTMPDIR=$(mktemp -d)

# local white lists
if [[ ! -e "$IP_WHITELIST_LOCAL" ]]; then
	touch "$IP_WHITELIST_LOCAL"
	IP_WHITELIST_LOCAL_TMP="$MYTMPDIR/ip_whitelist_local_tmp"
	cat > "$IP_WHITELIST_LOCAL_TMP" <<-EOF
	10.0.0.0/8
	127.0.0.0/8
	172.16.0.0/12
	192.168.0.0/16
	EOF
	for i in "${WHITELISTS_LOCAL[@]}"
	do
		FILE="$IP_BLACKLIST_DIR/$i"
		if [[ -e "$FILE" ]]; then
			[[ "$VERBOSE" == yes ]] && echo "Whitelisting IPs from $FILE"
			filterIPv4 "$FILE" >> "$IP_WHITELIST_LOCAL_TMP"
		else
			echo >&2 -e "\nError: WHITELIST_LOCAL: no such file: $FILE"
			exit 1
		fi
	done
	iprange "$IP_WHITELIST_LOCAL_TMP" > "$IP_WHITELIST_LOCAL"
	rm -f "$IP_WHITELIST_LOCAL_TMP"
fi

# remote black lists
if [[ ! -e "$IP_BLACKLIST_REMOTE" ]]; then
	touch "$IP_BLACKLIST_REMOTE"
	IP_BLACKLIST_TMP="$MYTMPDIR/ip_blacklist_tmp"
	CURL_ERROR=false
	COUNT=0
	for i in "${BLACKLISTS[@]}"
	do
		IP_TMP="$MYTMPDIR/ip_tmp"
		[[ "$VERBOSE" == yes ]] && echo "Retrieving $i"
		let HTTP_RC=$(curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$i")
		[[ "$VERBOSE" == yes ]] && echo "Response code: $HTTP_RC"
		if [ $HTTP_RC -eq 200 ] || [ $HTTP_RC -eq 302 ] || [ $HTTP_RC -eq 0 ]; then # "0" because file:/// returns 000
			filterIPv4 "$IP_TMP" >> "$IP_BLACKLIST_TMP"
			if [[ "$VERBOSE" == yes ]]; then
				NEWCOUNT=$(wc -l "$IP_BLACKLIST_TMP"|cut -d' ' -f1)
				echo "Adding $((NEWCOUNT-COUNT)) IPs from $i"
				COUNT=$NEWCOUNT
			fi
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
	iprange "$IP_BLACKLIST_TMP" > "$IP_BLACKLIST_REMOTE"
	rm -f "$IP_BLACKLIST_TMP"
fi

if [[ "$VERBOSE" == yes ]]; then
	echo -n "Remote blacklists entries:"
	wc -l "$IP_BLACKLIST_REMOTE"|cut -d' ' -f1
fi

# local black lists
if [[ ! -e "$IP_BLACKLIST_LOCAL" ]]; then
	touch "$IP_BLACKLIST_LOCAL"
	IP_BLACKLIST_LOCAL_TMP="$MYTMPDIR/ip_blacklist_local_tmp"
	COUNT=0
	for i in "${BLACKLISTS_LOCAL[@]}"
	do
		FILE="$IP_BLACKLIST_DIR/$i"
		if [[ -e "$FILE" ]]; then
			[[ "$VERBOSE" == yes ]] && echo "Blacklisting IPs from $FILE"
			filterIPv4 "$FILE" >> "$IP_BLACKLIST_LOCAL_TMP"
			if [[ "$VERBOSE" == yes ]]; then
				NEWCOUNT=$(wc -l "$IP_BLACKLIST_LOCAL_TMP"|cut -d' ' -f1)
				echo "Adding $((NEWCOUNT-COUNT)) IPs from $i"
				COUNT=$NEWCOUNT
			fi
		else
			echo >&2 -e "\nError: BLACKLIST_LOCAL: no such file: $FILE"
			exit 1
		fi
	done
	iprange "$IP_BLACKLIST_LOCAL_TMP" > "$IP_BLACKLIST_LOCAL"
	rm -f "$IP_BLACKLIST_LOCAL_TMP"
fi

iprange --union "$IP_BLACKLIST_REMOTE" "$IP_BLACKLIST_LOCAL" --except "$IP_WHITELIST_LOCAL" > "$IP_BLACKLIST"

IP_WHITELIST="$IP_WHITELIST_LOCAL"

# family = inet for IPv4 only
IPSET_BLACKLIST_OPTIONS="-exist hash:net family inet hashsize ${HASHSIZE:-16384} maxelem ${MAXELEM:-65536}"
IPSET_BLACKLIST_CREATE="create $IPSET_BLACKLIST_NAME $IPSET_BLACKLIST_OPTIONS"
IPSET_TMP_BLACKLIST_CREATE="create $IPSET_TMP_BLACKLIST_NAME $IPSET_BLACKLIST_OPTIONS"
cat >| "$IP_BLACKLIST_RESTORE" <<EOF
$IPSET_TMP_BLACKLIST_CREATE
$IPSET_BLACKLIST_CREATE
flush $IPSET_TMP_BLACKLIST_NAME
EOF

(sed -rn -e '/^#|^$/d' \
	-e "s/^([0-9./]+).*/add $IPSET_TMP_BLACKLIST_NAME \1 nomatch/p" "$IP_WHITELIST"; \
 sed -rn -e '/^#|^$/d' \
	-e "s/^([0-9./]+).*/add $IPSET_TMP_BLACKLIST_NAME \1/p" "$IP_BLACKLIST" ) >> "$IP_BLACKLIST_RESTORE"

cat >> "$IP_BLACKLIST_RESTORE" <<EOF
swap $IPSET_BLACKLIST_NAME $IPSET_TMP_BLACKLIST_NAME
destroy $IPSET_TMP_BLACKLIST_NAME
EOF

if [[ "$VERBOSE" == yes ]]; then
    echo
    echo -n "Number of whitelisted IP/networks found: "
    wc -l "$IP_WHITELIST" | cut -d' ' -f1
    echo -n "Number of blacklisted IP/networks found: "
    wc -l "$IP_BLACKLIST" | cut -d' ' -f1
    echo "Ipset restore file written to: $IP_BLACKLIST_RESTORE"
fi

# create set script
cat > "$IP_BLACKLIST_DIR/ip-blacklist.set.sh" <<EOSCRIPT
#!/bin/bash

IPSET_RESTORE="\$1"

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

if ! iptables -nvL INPUT|command grep -q "match-set $IPSET_BLACKLIST_NAME"; then
	if ! iptables -I INPUT "${IPTABLES_IPSET_RULE_NUMBER:-1}" -m set --match-set "$IPSET_BLACKLIST_NAME" src -j DROP; then
		echo >&2 "Error: while adding the --match-set ipset rule to iptables"
		exit 1
	fi
fi

if ! ipset -file "\${IPSET_RESTORE:-$IP_BLACKLIST_RESTORE}" restore; then
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

if iptables -nvL INPUT|command grep -q "match-set $IPSET_BLACKLIST_NAME"; then
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
