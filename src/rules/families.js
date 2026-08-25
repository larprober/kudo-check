'use strict';

/**
 * Malware family taxonomy used by the classifier.
 *
 *  weightCap   - maximum score a single family can contribute
 *  minRules    - distinct signatures required before the family may be named
 *  requires    - tag groups that must ALL be present for a confident naming.
 *                Each entry is an array of tags; at least one tag per entry
 *                must have been observed. Prevents "ransomware" being called
 *                on a lone AES import.
 *  blurb       - human explanation printed in the verdict
 */

const FAMILIES = {
  infostealer: {
    label: 'Infostealer',
    icon: 'stealer',
    weightCap: 100,
    minRules: 2,
    requires: [['credential-store', 'token-grab', 'wallet-theft', 'keychain']],
    blurb: 'Harvests credentials, session tokens, browser data or wallets from the host and ships them off-box.'
  },
  rat: {
    label: 'RAT / Backdoor',
    icon: 'rat',
    weightCap: 100,
    minRules: 2,
    requires: [['remote-shell', 'c2-beacon', 'remote-exec']],
    blurb: 'Gives an operator interactive or command-driven control of the machine after execution.'
  },
  ransomware: {
    label: 'Ransomware',
    icon: 'ransom',
    weightCap: 100,
    minRules: 2,
    requires: [['bulk-encrypt'], ['ransom-note', 'shadow-delete', 'recovery-kill', 'extension-rename']],
    blurb: 'Encrypts user files at scale and destroys recovery paths to force payment.'
  },
  wiper: {
    label: 'Wiper / Destructive',
    icon: 'wiper',
    weightCap: 100,
    minRules: 1,
    requires: [['destructive']],
    blurb: 'Deletes, overwrites or corrupts data or system state with no recovery intent.'
  },
  cryptominer: {
    label: 'Cryptominer',
    icon: 'miner',
    weightCap: 90,
    minRules: 1,
    requires: [['mining']],
    blurb: 'Silently spends the host CPU/GPU mining cryptocurrency for someone else.'
  },
  clipper: {
    label: 'Clipboard Hijacker',
    icon: 'clipper',
    weightCap: 90,
    minRules: 2,
    requires: [['clipboard'], ['wallet-address', 'wallet-theft']],
    blurb: 'Watches the clipboard and swaps copied wallet addresses for the attacker\u2019s own.'
  },
  keylogger: {
    label: 'Keylogger',
    icon: 'keylog',
    weightCap: 90,
    minRules: 1,
    requires: [['keylog']],
    blurb: 'Records keystrokes, usually alongside a window-title log, and stores or exfiltrates them.'
  },
  spyware: {
    label: 'Spyware / Surveillance',
    icon: 'spy',
    weightCap: 85,
    minRules: 2,
    requires: [['surveillance']],
    blurb: 'Captures screen, camera, microphone or location without the user asking for it.'
  },
  loader: {
    label: 'Loader / Dropper',
    icon: 'loader',
    weightCap: 90,
    minRules: 2,
    requires: [['remote-payload'], ['exec-payload', 'write-exec', 'memory-exec']],
    blurb: 'Pulls a second-stage payload from the network and runs it, usually without ever showing it in the repo.'
  },
  botnet: {
    label: 'Botnet / DDoS Node',
    icon: 'botnet',
    weightCap: 85,
    minRules: 2,
    requires: [['flood', 'bot-c2']],
    blurb: 'Enrols the host in a controlled swarm used for flooding or distributed abuse.'
  },
  worm: {
    label: 'Worm / Spreader',
    icon: 'worm',
    weightCap: 85,
    minRules: 2,
    requires: [['self-spread']],
    blurb: 'Copies itself onto other media, shares or contacts to keep propagating.'
  },
  rootkit: {
    label: 'Rootkit / Evasion',
    icon: 'evasion',
    weightCap: 80,
    minRules: 2,
    requires: [['av-tamper', 'amsi', 'hollowing', 'kernel-driver', 'anti-analysis']],
    blurb: 'Actively fights inspection: disables defences, patches runtime security, or hides its own execution.'
  },
  persistence: {
    label: 'Persistence Implant',
    icon: 'persist',
    weightCap: 70,
    minRules: 1,
    requires: [['persist']],
    blurb: 'Installs itself to survive reboot via autorun, service, task, cron or login item.'
  },
  supplychain: {
    label: 'Supply-chain Attack',
    icon: 'supply',
    weightCap: 95,
    minRules: 1,
    requires: [['install-hook', 'typosquat', 'dep-confusion']],
    blurb: 'Attacks whoever installs or builds the project, before any of its code is intentionally run.'
  },
  packer: {
    label: 'Obfuscated / Packed',
    icon: 'packed',
    weightCap: 70,
    minRules: 1,
    requires: [['obfuscation']],
    blurb: 'Hides its real logic behind encoding, packing or generated code. Not malicious by itself \u2014 but it is how payloads travel.'
  },
  hacktool: {
    label: 'HackTool / Riskware',
    icon: 'hacktool',
    weightCap: 85,
    minRules: 2,
    requires: [['proc-inject', 'hacktool-feature', 'kernel-driver']],
    blurb: 'Dual-use tooling: injects code into other processes, edits their memory, or maps unsigned drivers. Normal in a debugger, alarming in a game mod or a helper utility.'
  },
  phishing: {
    label: 'Phishing / Credential Harvester',
    icon: 'phish',
    weightCap: 80,
    minRules: 2,
    requires: [['fake-login']],
    blurb: 'Impersonates a real login surface to collect the credentials a human types into it.'
  },
  adware: {
    label: 'Adware / PUP',
    icon: 'adware',
    weightCap: 60,
    minRules: 2,
    requires: [['adware']],
    blurb: 'Injects ads, hijacks search or homepage, or bundles unrequested software.'
  }
};

/** MITRE-flavoured tactic buckets used for the capability profile. */
const TACTICS = {
  execution:      'Execution',
  persistence:    'Persistence',
  privesc:        'Privilege Escalation',
  evasion:        'Defense Evasion',
  credaccess:     'Credential Access',
  discovery:      'Discovery',
  lateral:        'Lateral Movement',
  collection:     'Collection',
  c2:             'Command & Control',
  exfiltration:   'Exfiltration',
  impact:         'Impact'
};

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

module.exports = { FAMILIES, TACTICS, SEVERITY_ORDER };
