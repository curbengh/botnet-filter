# Botnet IP Blocklist

- Formats
  - [IP-based](#ip-based)
  - [Domain-based (AdGuard Home)](#domain-based-adguard-home)
  - [IP-based (AdGuard)](#ip-based-adguard)
  - [IP-based (Vivaldi)](#ip-based-vivaldi)
  - [dnscrypt-proxy](#dnscrypt-proxy)
  - [Snort2](#snort2)
  - [Snort3](#snort3)
  - [Suricata](#suricata)
  - [Splunk](#splunk)
  - [htaccess](#htaccess)
- [Compressed version](#compressed-version)
- [Reporting issues](#issues)
- [FAQ and Guides](#faq-and-guides)
- [CI Variables](#ci-variables)
- [License](#license)

A blocklist of malicious IPs compiled from these sources (discovered through [banip](https://github.com/openwrt/packages/blob/master/net/banip/files/banip.feeds)):
  - [Feodo Tracker](https://feodotracker.abuse.ch/downloads/ipblocklist.txt)
  - [IPsum Level 3](https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt)
  - [Binary Defense](https://www.binarydefense.com/banlist.txt)
  - [Proofpoint Emerging Threats](https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
  - [GreenSnow](https://blocklist.greensnow.co/greensnow.txt)
  - [Threatview.io](https://threatview.io/Downloads/IP-High-Confidence-Feed.txt)
  - [Myip.ms](https://myip.ms/files/blacklist/general/latest_blacklist.txt)
  - [FireHOL](https://iplists.firehol.org/files/firehol_webclient.netset)

Blocklist is updated twice a day.

| Client | mirror 1 | mirror 2 | mirror 3 | mirror 4 | mirror 5 | mirror 6 |
| --- | --- | --- | --- | --- | --- | --- |
| uBlock Origin, [IP-based](#ip-based) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt) | [link](https://curbengh.github.io/malware-filter/botnet-filter.txt) | [link](https://curbengh.github.io/botnet-filter/botnet-filter.txt) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter.txt) | [link](https://malware-filter.pages.dev/botnet-filter.txt) | [link](https://botnet-filter.pages.dev/botnet-filter.txt) |
| [AdGuard Home](#domain-based-adguard-home) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt) | [link](https://curbengh.github.io/malware-filter/botnet-filter-agh.txt) | [link](https://curbengh.github.io/botnet-filter/botnet-filter-agh.txt) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter-agh.txt) | [link](https://malware-filter.pages.dev/botnet-filter-agh.txt) | [link](https://botnet-filter.pages.dev/botnet-filter-agh.txt) |
| [AdGuard (browser extension)](#ip-based-adguard) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter-ag.txt) | [link](https://curbengh.github.io/malware-filter/botnet-filter-ag.txt) | [link](https://curbengh.github.io/botnet-filter/botnet-filter-ag.txt) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter-ag.txt) | [link](https://malware-filter.pages.dev/botnet-filter-ag.txt) | [link](https://botnet-filter.pages.dev/botnet-filter-ag.txt) |
| [Vivaldi](#ip-based-vivaldi) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter-vivaldi.txt) | [link](https://curbengh.github.io/malware-filter/botnet-filter-vivaldi.txt) | [link](https://curbengh.github.io/botnet-filter/botnet-filter-vivaldi.txt) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter-vivaldi.txt) | [link](https://malware-filter.pages.dev/botnet-filter-vivaldi.txt) | [link](https://botnet-filter.pages.dev/botnet-filter-vivaldi.txt) |
| [dnscrypt-proxy](#dnscrypt-proxy) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter-dnscrypt-blocked-ips.txt) | [link](https://curbengh.github.io/malware-filter/botnet-filter-dnscrypt-blocked-ips.txt) | [link](https://curbengh.github.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter-dnscrypt-blocked-ips.txt) | [link](https://malware-filter.pages.dev/botnet-filter-dnscrypt-blocked-ips.txt) | [link](https://botnet-filter.pages.dev/botnet-filter-dnscrypt-blocked-ips.txt) |
| [Snort2](#snort2), [Snort3](#snort3), [Suricata](#suricata) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter-suricata.rules) | [link](https://curbengh.github.io/malware-filter/botnet-filter-suricata.rules) | [link](https://curbengh.github.io/botnet-filter/botnet-filter-suricata.rules) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter-suricata.rules) | [link](https://malware-filter.pages.dev/botnet-filter-suricata.rules) | [link](https://botnet-filter.pages.dev/botnet-filter-suricata.rules) |
| [Splunk](#splunk) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter-splunk.csv) | [link](https://curbengh.github.io/malware-filter/botnet-filter-splunk.csv) | [link](https://curbengh.github.io/botnet-filter/botnet-filter-splunk.csv) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter-splunk.csv) | [link](https://malware-filter.pages.dev/botnet-filter-splunk.csv) | [link](https://botnet-filter.pages.dev/botnet-filter-splunk.csv) |
| [Apache](#htaccess) | [link](https://malware-filter.gitlab.io/malware-filter/botnet-filter-htaccess.txt) | [link](https://curbengh.github.io/malware-filter/botnet-filter-htaccess.txt) | [link](https://curbengh.github.io/botnet-filter/botnet-filter-htaccess.txt) | [link](https://malware-filter.gitlab.io/botnet-filter/botnet-filter-htaccess.txt) | [link](https://malware-filter.pages.dev/botnet-filter-htaccess.txt) | [link](https://botnet-filter.pages.dev/botnet-filter-htaccess.txt) |

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [phishing-filter](https://gitlab.com/malware-filter/phishing-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)
- [vn-badsite-filter](https://gitlab.com/malware-filter/vn-badsite-filter)

## IP-based

Import the link into uBO's filter list to subscribe.

</details>

## IP-based (AdGuard)

Import the link into AdGuard browser extension to subscribe.

## IP-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the link into Vivaldi's **Tracker Blocking Sources** to subscribe.

## Domain-based (AdGuard Home)

## dnscrypt-proxy

Save the rulesets to "/etc/dnscrypt-proxy/". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_ips]
+  blocked_ips_file = '/etc/dnscrypt-proxy/botnet-filter-dnscrypt-blocked-ips.txt'
```

## Snort2

Save the ruleset to "/etc/snort/rules/botnet-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

`printf "\ninclude \$RULE_PATH/botnet-filter-suricata.rules\n" >> /etc/snort/snort.conf`

## Snort3

Save the ruleset to "/etc/snort/rules/botnet-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

```diff
# /etc/snort/snort.lua
ips =
{
  variables = default_variables,
+  include = 'rules/botnet-filter-suricata.rules'
}
```

## Suricata

Save the ruleset to "/etc/suricata/rules/botnet-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - botnet-filter-suricata.rules
```

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutlookupsandfieldactions).

Either upload the file via GUI or save the file in `$SPLUNK_HOME/Splunk/etc/system/lookups` or app-specific `$SPLUNK_HOME/etc/YourApp/apps/search/lookups`.

Or use [malware-filter add-on](https://splunkbase.splunk.com/app/6970) to install this lookup and optionally auto-update it.

Columns:

| ip | message | updated |
| --- | --- | --- |
| 1.2.3.4 | botnet-filter botnet IP detected | 2022-12-21T12:34:56Z |

## htaccess

In Apache configuration, add `AllowOverride All` to each `<Directory>`, then add .htaccess to each site directory.

## Compressed version

All filters are also available as gzip- and brotli-compressed.

- Gzip: https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt.gz
- Brotli: https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt.br
- Zstd: https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt.zst

## Issues

This blocklist **only** accepts new malicious IPs from upstream [sources](#credits).

## FAQ and Guides

See [wiki](https://gitlab.com/malware-filter/malware-filter/-/wikis/home)

## CI Variables

Optional variables:

- `CLOUDFLARE_BUILD_HOOK`: Deploy to Cloudflare Pages.
- `NETLIFY_SITE_ID`: Deploy to Netlify.

## Repository Mirrors

https://gitlab.com/curben/blog#repository-mirrors

## License

[Creative Commons Zero v1.0 Universal](LICENSE-CC0.md) and [MIT License](LICENSE)

[Feodo Tracker](https://feodotracker.abuse.ch/): [CC0](https://creativecommons.org/publicdomain/zero/1.0/)

[IPsum Level 3](https://github.com/stamparm): [Unlicense](https://github.com/stamparm/ipsum/blob/master/LICENSE)

## Credits

[Binary Defense](https://www.binarydefense.com/)

[Proofpoint Emerging Threats](https://www.proofpoint.com/us/products/advanced-threat-protection/et-intelligence)

[GreenSnow](https://greensnow.co/)

[Threatview.io](https://threatview.io/)

[Myip.ms](https://myip.ms/files/blacklist/general/latest_blacklist.txt)

[FireHOL](https://iplists.firehol.org/files/firehol_webclient.netset)

[banip](https://github.com/openwrt/packages/blob/master/net/banip/files/)

This repository is not endorsed by Abuse.ch.
