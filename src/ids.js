import { createWriteStream } from 'node:fs'
import { open } from 'node:fs/promises'

const ips = await open('ip.txt')

const suricata = createWriteStream('../public/botnet-filter-suricata.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const splunk = createWriteStream('../public/botnet-filter-splunk.csv', {
  encoding: 'utf8',
  flags: 'a'
})

let sid = 600000001

for await (const line of ips.readLines()) {
  if (!URL.canParse(`http://${line}`)) {
    console.error(`Invalid URL: ${line}`)
    continue
  }

  const url = new URL(`http://${line}`)
  const suricataIp = url.hostname.replace(/\[|\]/g, '"')
  const splunkIp = url.hostname.replace(/\[|\]/g, '')

  suricata.write(`alert ip $HOME_NET any -> [${suricataIp}] any (msg:"botnet-filter botnet IP detected\"; classtype:trojan-activity; sid:${sid}; rev:1;)\n`)
  splunk.write(`"${splunkIp}","botnet-filter botnet IP detected","${process.env.CURRENT_TIME}"\n`)

  sid++
}

suricata.close()
splunk.close()
