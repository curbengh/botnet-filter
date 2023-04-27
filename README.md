# Botnet IP Blocklist

- Formats
  - [IP-based](#ip-based)
  - [Domain-based (AdGuard Home)](#domain-based-adguard-home)
  - [IP-based (AdGuard)](#ip-based-adguard)
  - [IP-based (Vivaldi)](#ip-based-vivaldi)
  - [dnscrypt-proxy](#dnscrypt-proxy)
  - [Snort2](#)
  - [Snort3](#snort3)
  - [Suricata](#suricata)
  - [Splunk](#splunk)
- [Compressed version](#compressed-version)
- [Reporting issues](#issues)
- [FAQ and Guides](#faq-and-guides)
- [CI Variables](#ci-variables)
- [License](#license)

A blocklist of botnet IPs, based on the **Botnet C2 IOCs** of Abuse.ch [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/#iocs), including online and offline entries. Blocklist is updated twice a day.

This blocklist is only useful as a last line of defence _after_ being infected. To avoid infection in the first place, consider using [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter).

There are multiple formats available, refer to the appropriate section according to the program used:

- uBlock Origin (uBO) -> [IP-based](#ip-based) section (recommended)
- Pi-hole -> [Domain-based](#domain-based) or [Hosts-based](#hosts-based) section
- AdGuard Home -> [Domain-based (AdGuard Home)](#domain-based-adguard-home)
- AdGuard browser extension -> [IP-based (AdGuard)](#ip-based-adguard)
- Vivaldi -> [IP-based (Vivaldi)](#ip-based-vivaldi)
- [dnscrypt-proxy](#dnscrypt-proxy)
- [Snort2](#snort2)
- [Snort3](#snort3)
- [Suricata](#suricata)
- [Splunk](#splunk)

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [phishing-filter](https://gitlab.com/malware-filter/phishing-filter)
- [pup-filter](https://gitlab.com/malware-filter/pup-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)
- [vn-badsite-filter](https://gitlab.com/malware-filter/vn-badsite-filter)

## IP-based

I highly recommend to use the upstream version (update every 5 minutes): [online+offline](https://feodotracker.abuse.ch/downloads/ipblocklist.txt) or [online only](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt).

Import the following URL into uBO to subscribe:

- https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter.txt
- https://curbengh.github.io/botnet-filter/botnet-filter.txt
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter.txt
- https://malware-filter.pages.dev/botnet-filter.txt
- https://botnet-filter.pages.dev/botnet-filter.txt

</details>

## IP-based (AdGuard)

Import the following URL into AdGuard browser extension to subscribe:

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-ag.txt
- https://curbengh.github.io/botnet-filter/botnet-filter-ag.txt
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-ag.txt
- https://malware-filter.pages.dev/botnet-filter-ag.txt
- https://botnet-filter.pages.dev/botnet-filter-ag.txt

</details>

## IP-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the following URL into Vivaldi's **Tracker Blocking Sources** to subscribe:

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-vivaldi.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-vivaldi.txt
- https://curbengh.github.io/botnet-filter/botnet-filter-vivaldi.txt
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-vivaldi.txt
- https://malware-filter.pages.dev/botnet-filter-vivaldi.txt
- https://botnet-filter.pages.dev/botnet-filter-vivaldi.txt

</details>

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses.

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-agh.txt
- https://curbengh.github.io/botnet-filter/botnet-filter-agh.txt
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-agh.txt
- https://malware-filter.pages.dev/botnet-filter-agh.txt
- https://botnet-filter.pages.dev/botnet-filter-agh.txt

</details>

## dnscrypt-proxy

Save the rulesets to "/etc/dnscrypt-proxy/". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_ips]
+  blocked_ips_file = '/etc/dnscrypt-proxy/botnet-filter-dnscrypt-blocked-ips.txt'
```

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-dnscrypt-blocked-ips.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-dnscrypt-blocked-ips.txt
- https://curbengh.github.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt
- https://malware-filter.pages.dev/botnet-filter-dnscrypt-blocked-ips.txt
- https://botnet-filter.pages.dev/botnet-filter-dnscrypt-blocked-ips.txt

</details>

## Snort2

I highly recommend to use the [upstream version](https://feodotracker.abuse.ch/blocklist/#ip-ids) which is updated every 5 minutes.

Save the ruleset to "/etc/snort/rules/botnet-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update. Snort 2, 3 and Suricata use the same ruleset for this blocklist.

Configure Snort to use the ruleset:

`printf "\ninclude \$RULE_PATH/botnet-filter-suricata.rules\n" >> /etc/snort/snort.conf`

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-suricata.rules
- https://curbengh.github.io/botnet-filter/botnet-filter-suricata.rules
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-suricata.rules
- https://malware-filter.pages.dev/botnet-filter-suricata.rules
- https://botnet-filter.pages.dev/botnet-filter-suricata.rules

</details>

## Snort3

I highly recommend to use the [upstream version](https://feodotracker.abuse.ch/blocklist/#ip-ids) which is updated every 5 minutes.

Save the ruleset to "/etc/snort/rules/botnet-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update. Snort 2, 3 and Suricata use the same ruleset for this blocklist.

Configure Snort to use the ruleset:

```diff
# /etc/snort/snort.lua
ips =
{
  variables = default_variables,
+  include = 'rules/botnet-filter-suricata.rules'
}
```

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-suricata.rules
- https://curbengh.github.io/botnet-filter/botnet-filter-suricata.rules
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-suricata.rules
- https://malware-filter.pages.dev/botnet-filter-suricata.rules
- https://botnet-filter.pages.dev/botnet-filter-suricata.rules

</details>

## Suricata

I highly recommend to use the [upstream version](https://feodotracker.abuse.ch/blocklist/#ip-ids) which is updated every 5 minutes.

Save the ruleset to "/etc/suricata/rules/botnet-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update. Snort 2, 3 and Suricata use the same ruleset for this blocklist.

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - botnet-filter-suricata.rules
```

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-suricata.rules
- https://curbengh.github.io/botnet-filter/botnet-filter-suricata.rules
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-suricata.rules
- https://malware-filter.pages.dev/botnet-filter-suricata.rules
- https://botnet-filter.pages.dev/botnet-filter-suricata.rules

</details>

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/9.0.2/Knowledge/Aboutlookupsandfieldactions).

Either upload the file via GUI or save the file in `$SPLUNK_HOME/Splunk/etc/system/lookups` or app-specific `$SPLUNK_HOME/etc/YourApp/apps/search/lookups`. Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) or [Getwatchlist](https://splunkbase.splunk.com/app/635) app for auto-update.

Columns:

| ip      | message                          | updated              |
| ------- | -------------------------------- | -------------------- |
| 1.2.3.4 | botnet-filter botnet IP detected | 2022-12-21T12:34:56Z |

- https://malware-filter.gitlab.io/malware-filter/botnet-filter-splunk.csv

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/botnet-filter-splunk.csv
- https://curbengh.github.io/botnet-filter/botnet-filter-splunk.csv
- https://malware-filter.gitlab.io/botnet-filter/botnet-filter-splunk.csv
- https://malware-filter.pages.dev/botnet-filter-splunk.csv
- https://botnet-filter.pages.dev/botnet-filter-splunk.csv

</details>

## Compressed version

All filters are also available as gzip- and brotli-compressed.

- Gzip: https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt.gz
- Brotli: https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt.br

## Issues

This blocklist **only** accepts new malicious IPs from [Feodo Tracker](https://feodotracker.abuse.ch/).

## FAQ and Guides

See [wiki](https://gitlab.com/malware-filter/malware-filter/-/wikis/home)

## CI Variables

Optional variables:

- `CLOUDFLARE_BUILD_HOOK`: Deploy to Cloudflare Pages.
- `NETLIFY_SITE_ID`: Deploy to Netlify.

## License

[Creative Commons Zero v1.0 Universal](LICENSE-CC0.md) and [MIT License](LICENSE-CC0.md)

[Feodo Tracker](https://feodotracker.abuse.ch/): [CC0](https://creativecommons.org/publicdomain/zero/1.0/)

This repository is not endorsed by Abuse.ch.
