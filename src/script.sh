#!/bin/sh

## dash does not support pipefail
# this does not work in `dash script.sh`
DASH=$(readlink -f "/bin/sh" | grep "dash" || [ $? = 1 ])
if [ -n "$DASH" ]; then
  set -efx
else
  set -efx -o pipefail
fi

alias curl="curl -L"
alias mkdir="mkdir -p"
alias rm="rm -rf"

## Use GNU grep, busybox grep is not as performant
. "/etc/os-release"
DISTRO="$ID"

check_grep() {
  if [ -z "$(grep --help | grep 'GNU')" ]; then
    if [ -x "/usr/bin/grep" ]; then
      echo "grep found. try alias"
      alias grep="/usr/bin/grep"
      check_grep
    else
      if [ "$DISTRO" = "alpine" ]; then
        echo "Please install GNU grep 'apk add grep'"
      else
        echo "GNU grep not found"
      fi
      exit 1
    fi
  fi
}
check_grep


## Fallback to busybox's dos2unix if installed
if ! command -v dos2unix &> /dev/null
then
  if command -v busybox &> /dev/null
  then
    alias dos2unix="busybox dos2unix"
  else
    echo "dos2unix or busybox not found"
    exit 1
  fi
fi


## Create a temporary working folder
mkdir "tmp/"
cd "tmp/"

## Prepare datasets
curl "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" -o "feodo.csv"

## Parse IPs
cat "feodo.csv" | \
dos2unix | \
# Remove comment
sed "/^#/d" | \
# dst_ip column
cut -f 4 -d '"' | \
# Remove header row
tail -n +2 | \
sort -u > "feodo-ip.txt"

## Merge malware domains and URLs
CURRENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMENT_UBO="! Title: Botnet IP Blocklist\n"
COMMENT_UBO="$COMMENT_UBO! Updated: $CURRENT_TIME\n"
COMMENT_UBO="$COMMENT_UBO! Expires: 1 day (update frequency)\n"
COMMENT_UBO="$COMMENT_UBO! Homepage: https://gitlab.com/malware-filter/botnet-filter\n"
COMMENT_UBO="$COMMENT_UBO! License: https://gitlab.com/malware-filter/botnet-filter#license\n"
COMMENT_UBO="$COMMENT_UBO! Source: https://feodotracker.abuse.ch/blocklist/"

mkdir "../public/"

# uBlock Origin
cat "feodo-ip.txt" | \
sed "1i $COMMENT_UBO" > "../public/botnet-filter.txt"


# Adguard Home
cat "feodo-ip.txt" | \
sed -e "s/^/||/g" -e "s/$/^/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard Home)/" > "../public/botnet-filter-agh.txt"


# Adguard browser extension
cat "feodo-ip.txt" | \
sed -e "s/^/||/g" -e "s/$/\$all/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard)/" > "../public/botnet-filter-ag.txt"


# Vivaldi
cat "feodo-ip.txt" | \
sed -e "s/^/||/g" -e "s/$/\$document/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (Vivaldi)/" > "../public/botnet-filter-vivaldi.txt"


## Hash comment
# awk + head is a workaround for sed prepend
COMMENT=$(printf "$COMMENT_UBO" | sed "s/^!/#/g" | awk '{printf "%s\\n", $0}' | head -c -2)


## dnscrypt-proxy blocklists
# name-based
cat "feodo-ip.txt" | \
sed "1i $COMMENT" | \
sed "1s/Domains/IPs/" > "../public/botnet-filter-dnscrypt-blocked-ips.txt"


## Temporarily disable command print
set +x


## Snort & Suricata rulesets
rm "../public/botnet-filter-suricata.rules" \
  "../public/botnet-filter-splunk.csv"

SID="600000001"
while read IP; do
  SR_RULE="alert ip \$HOME_NET any -> [$IP] any (msg:\"botnet-filter botnet IP detected\"; reference:url, feodotracker.abuse.ch/browse/host/$IP/; classtype:trojan-activity; sid:$SID; rev:1;)"

  SP_RULE="\"$IP\",\"botnet-filter botnet IP detected\",\"$CURRENT_TIME\""

  echo "$SR_RULE" >> "../public/botnet-filter-suricata.rules"
  echo "$SP_RULE" >> "../public/botnet-filter-splunk.csv"

  SID=$(( $SID + 1 ))
done < "feodo-ip.txt"


set -x


sed -i "1i $COMMENT" "../public/botnet-filter-suricata.rules"
sed -i "1s/Blocklist/Suricata Ruleset/" "../public/botnet-filter-suricata.rules"

sed -i -e "1i $COMMENT" -e '1i "ip","message","updated"' "../public/botnet-filter-splunk.csv"
sed -i "1s/Blocklist/Splunk Lookup/" "../public/botnet-filter-splunk.csv"


cd ../
