#!/bin/sh

if ! (set -o pipefail 2>/dev/null); then
  # dash does not support pipefail
  set -efx
else
  set -efx -o pipefail
fi

# bash does not expand alias by default for non-interactive script
if [ -n "$BASH_VERSION" ]; then
  shopt -s expand_aliases
fi

alias curl="curl -L"
alias mkdir="mkdir -p"
alias rm="rm -rf"

## Use GNU grep, busybox grep is not as performant
DISTRO=""
if [ -f "/etc/os-release" ]; then
  . "/etc/os-release"
  DISTRO="$ID"
fi

check_grep() {
  if [ -z "$(grep --help | grep 'GNU')" ]; then
    if [ -x "/usr/bin/grep" ]; then
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
curl "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" -o "feodo.txt" || [ $? = 1 ]
curl "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" -o "ipsum-level3.txt" || [ $? = 1 ]
curl "https://www.binarydefense.com/banlist.txt" -o "binarydefense.txt" || [ $? = 1 ]
curl "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" -o "et.txt" || [ $? = 1 ]
curl "https://blocklist.greensnow.co/greensnow.txt" -o "greensnow.txt" || [ $? = 1 ]
curl "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt" -o "threatview.txt" || [ $? = 1 ]
# missing intermediate cert
curl "https://myip.ms/files/blacklist/general/latest_blacklist.txt" --cacert "../src/globalsign-sub.pem" -o "myip.txt" || [ $? = 1 ]
curl "https://iplists.firehol.org/files/firehol_webclient.netset" -o "firehol-web.txt" || [ $? = 1 ]

# ensure file exists
touch "feodo.txt" "ipsum-level3.txt" "binarydefense.txt" "et.txt" "greensnow.txt" "threatview.txt" "myip.txt" "firehol-web.txt"


## Parse IPs
cat "feodo.txt" "ipsum-level3.txt" "binarydefense.txt" "et.txt" "greensnow.txt" "threatview.txt" "myip.txt" "firehol-web.txt" | \
dos2unix | \
# Remove comment
sed "/^#/d" | \
# Remove inline comment
sed -r "s/\s.+//g" | \
# Remove blank lines
sed "/^$/d" | \
# Wrap ipv6 in bracket
sed -r "s/(.+:.+)/[\1]/" | \
sort -u > "ip.txt"

## Merge malware domains and URLs
CURRENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMENT_UBO="! Title: Malicious IP Blocklist\n"
COMMENT_UBO="$COMMENT_UBO! Updated: $CURRENT_TIME\n"
COMMENT_UBO="$COMMENT_UBO! Expires: 12 hours (update frequency)\n"
COMMENT_UBO="$COMMENT_UBO! Homepage: https://gitlab.com/malware-filter/botnet-filter\n"
COMMENT_UBO="$COMMENT_UBO! License: https://gitlab.com/malware-filter/botnet-filter#license\n"
COMMENT_UBO="$COMMENT_UBO! Source: feodotracker.abuse.ch, stamparm/ipsum, binarydefense, Proofpoint emergingthreats, greensnow, threatview, myip.ms, firehol"

mkdir "../public/"

# uBlock Origin
cat "ip.txt" | \
sed "1i $COMMENT_UBO" > "../public/botnet-filter.txt"


# Adguard Home
cat "ip.txt" | \
sed -e "s/^/||/g" -e "s/$/^/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard Home)/" > "../public/botnet-filter-agh.txt"


# Adguard browser extension
cat "ip.txt" | \
sed -e "s/^/||/g" -e "s/$/\$all/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard)/" > "../public/botnet-filter-ag.txt"


# Vivaldi
cat "ip.txt" | \
sed -e "s/^/||/g" -e "s/$/\$document/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (Vivaldi)/" > "../public/botnet-filter-vivaldi.txt"

## Hash comment
# awk + head is a workaround for sed prepend
COMMENT=$(printf "$COMMENT_UBO" | sed "s/^!/#/g" | awk '{printf "%s\\n", $0}' | head -c -2)


## dnscrypt-proxy blocklists
# IP-based
cat "ip.txt" | \
sed -r "s/\[|\]//g" | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/Blocklist (Dnscrypt-proxy)/" > "../public/botnet-filter-dnscrypt-blocked-ips.txt"


## htaaccess
cat "ip.txt" | \
sed -r "s/\[|\]//g" | \
sed "s/^/deny from /g" | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/Blocklist (htaccess)/" > "../public/botnet-filter-htaccess.txt"


## Temporarily disable command print
set +x


## Snort & Suricata rulesets
rm "../public/botnet-filter-suricata.rules" \
  "../public/botnet-filter-splunk.csv"

export CURRENT_TIME
node "../src/ids.js"


set -x


sed -i "1i $COMMENT" "../public/botnet-filter-suricata.rules"
sed -i "1s/Blocklist/Suricata Ruleset/" "../public/botnet-filter-suricata.rules"

sed -i -e "1i $COMMENT" -e '1i "ip","message","updated"' "../public/botnet-filter-splunk.csv"
sed -i "1s/Blocklist/Splunk Lookup/" "../public/botnet-filter-splunk.csv"


cd ../
