'use strict';

/* KUDO-SIGNATURE-DATABASE — this marker tells Kudo Check that the patterns below
   are detection rules, not malware. Scanners that scan themselves are useless. */

/**
 * Kudo Check signature set.
 *
 * Rules are line-oriented by default: the scanner lowercases each line once,
 * does a cheap `hint` substring test, and only then runs the regex. Rules
 * marked `span:true` run against the whole file with bounded gaps.
 *
 *   weight  0-30   score contributed to the family on first hit
 *   tags           feed FAMILIES[...].requires gating in classify.js
 *   ext            restrict to these file extensions (omit = all text files)
 */

const R = [];

function s(id, o) {
  if (!o.name || !o.family || !o.re) throw new Error('bad signature ' + id);
  if (R.some((r) => r.id === id)) throw new Error('duplicate signature id ' + id);
  R.push({
    id,
    name: o.name,
    family: o.family,
    tactic: o.tactic || 'execution',
    severity: o.severity || 'medium',
    weight: o.weight == null ? 10 : o.weight,
    tags: o.tags || [],
    re: o.re,
    hint: o.hint || null,
    ext: o.ext || null,
    span: !!o.span,
    why: o.why || ''
  });
}

/* ─────────────────────────────  INFOSTEALER  ───────────────────────────── */

s('STL-001', {
  name: 'Chromium credential database access',
  family: 'infostealer', tactic: 'credaccess', severity: 'critical', weight: 26,
  tags: ['credential-store'], hint: 'login data',
  re: /Login\s?Data|Web\s?Data["'`]/i,
  why: 'Chromium keeps saved passwords in "Login Data". Reading that file has no legitimate in-app use.'
});

s('STL-002', {
  name: 'Browser cookie store harvesting',
  family: 'infostealer', tactic: 'credaccess', severity: 'critical', weight: 24,
  tags: ['credential-store'], hint: 'cookies',
  // "get" is deliberately absent: getCookies() is ordinary web-app code.
  re: /Network[\\/]Cookies|moz_cookies|browser_cookie3|(?:steal|dump|exfil)_?cookies\b|grab_cookies\b/i,
  why: 'Copying the cookie database lifts live sessions, which bypasses both the password and 2FA.'
});

s('STL-003', {
  name: 'DPAPI decryption of browser secrets',
  family: 'infostealer', tactic: 'credaccess', severity: 'critical', weight: 26,
  tags: ['credential-store'], hint: 'unprotect',
  re: /CryptUnprotectData|ProtectedData\.Unprotect/i,
  why: 'DPAPI unprotect is exactly the step that turns an encrypted browser password blob back into plaintext.'
});

s('STL-004', {
  name: 'Discord local storage token grab',
  family: 'infostealer', tactic: 'credaccess', severity: 'critical', weight: 28,
  tags: ['token-grab'], hint: 'discord',
  re: /discord[^\n]{0,50}(?:Local\s?Storage|leveldb)|(?:Local\s?Storage|leveldb)[^\n]{0,50}discord/i,
  why: 'Reading Discord\u2019s leveldb store is the canonical token-grabber move.'
});

s('STL-005', {
  name: 'Discord authentication token pattern',
  family: 'infostealer', tactic: 'credaccess', severity: 'critical', weight: 22,
  tags: ['token-grab'], hint: '{24}',
  re: /\[\\?w-\]\{24\}\\?\.\[\\?w-\]\{6\}|[A-Za-z\\d]\{24\}\\?\.[^\n]{0,12}\{6\}|\bmfa\.[\w-]{60,}/,
  why: 'This regex shape matches nothing except a Discord authentication token.'
});

s('STL-006', {
  name: 'Cryptocurrency wallet file theft',
  family: 'infostealer', tactic: 'collection', severity: 'critical', weight: 26,
  tags: ['wallet-theft'], hint: 'wallet',
  re: /wallet\.dat|exodus\.wallet|Ethereum[\\/]keystore|Electrum[\\/]wallets|(?:Atomic|Guarda|Coinomi|Jaxx)[\\/][^\n]{0,40}(?:Local\s?Storage|leveldb)|nkbihfbeogaeaoehlefnkodbefgpgknn/i,
  why: 'These are on-disk wallet stores, or the MetaMask extension id. Copying them is theft of funds.'
});

s('STL-007', {
  name: 'macOS keychain dumping',
  family: 'infostealer', tactic: 'credaccess', severity: 'high', weight: 22,
  tags: ['keychain'], hint: 'keychain',
  re: /login\.keychain(?:-db)?|security\s+(?:dump|find-generic|find-internet)-?password/i,
  why: 'Dumping the login keychain extracts every stored macOS credential in one call.'
});

s('STL-008', {
  name: 'SSH and cloud credential sweep',
  family: 'infostealer', tactic: 'credaccess', severity: 'high', weight: 20,
  tags: ['credential-store'], hint: 'id_rsa',
  re: /\.ssh[\\/](?:id_rsa|id_ed25519|authorized_keys)|\.aws[\\/]credentials|\.config[\\/]gcloud|\.kube[\\/]config|\.docker[\\/]config\.json/i,
  why: 'Collecting private keys and cloud credential files in bulk is theft, not configuration.'
});

s('STL-009', {
  name: 'Environment variable exfiltration',
  family: 'infostealer', tactic: 'collection', severity: 'high', weight: 20,
  tags: ['credential-store'], hint: 'env',
  re: /JSON\.stringify\(\s*(?:process\.)?env\s*\)|(?:post|send|fetch|axios|requests)[^\n]{0,60}(?:process\.env|os\.environ)\s*[,)]/i,
  why: 'Serialising the whole environment into a request body ships every secret the process can see.'
});

s('STL-010', {
  name: 'SQL against browser secret tables',
  family: 'infostealer', tactic: 'collection', severity: 'high', weight: 22,
  tags: ['credential-store'], hint: 'select',
  re: /SELECT[^\n]{0,80}FROM\s+(?:logins|credit_cards|autofill|cookies|moz_cookies|moz_logins)\b/i,
  why: 'Direct SQL against the browser\u2019s saved-login or saved-card tables.'
});

s('STL-011', {
  name: 'Telegram or Steam session theft',
  family: 'infostealer', tactic: 'collection', severity: 'high', weight: 20,
  tags: ['token-grab'], hint: 'tdata',
  re: /tdata["'`\\/]|Telegram\s?Desktop[\\/]tdata|\bssfn\d{6,}|loginusers\.vdf/i,
  why: 'Telegram tdata and Steam ssfn files are portable session credentials \u2014 copy them and you are logged in.'
});

s('STL-012', {
  name: 'Game account session theft',
  family: 'infostealer', tactic: 'collection', severity: 'high', weight: 18,
  tags: ['token-grab'], hint: 'roblosecurity',
  re: /\.ROBLOSECURITY|launcher_accounts\.json|launcher_profiles\.json[^\n]{0,40}(?:read|open|copy)/i,
  why: 'These files hold a logged-in game session; stealers grab them to hijack accounts.'
});

s('STL-013', {
  name: 'Filesystem sweep for secret-shaped filenames',
  family: 'infostealer', tactic: 'collection', severity: 'medium', weight: 14,
  tags: ['credential-store'], hint: 'seed',
  re: /(?:seed|passw|wallet|backup|secret|metamask|2fa|recovery)[^\n]{0,25}\.(?:txt|docx?|pdf|jpg|png)["'`]|(?:glob|walk|listdir)[^\n]{0,50}(?:passw|wallet|seed)/i,
  why: 'Walking the disk for files named like secrets is a grabber sweep.'
});

s('STL-014', {
  name: 'Known stealer family or builder name',
  family: 'infostealer', tactic: 'collection', severity: 'critical', weight: 26,
  tags: ['token-grab', 'credential-store'], hint: 'stealer',
  re: /\b(?:redline\s?stealer|raccoon\s?stealer|vidar|lumma\s?c2|mystic\s?stealer|rhadamanthys|blank\s?grabber|creal\s?stealer|umbral\s?stealer|luna\s?grabber|empyrean|skuld\s?stealer)\b/i,
  why: 'Names a known commodity stealer family or its builder.'
});

s('STL-015', {
  name: 'Webhook exfiltration of collected data',
  family: 'infostealer', tactic: 'exfiltration', severity: 'critical', weight: 24,
  tags: ['credential-store'], hint: 'webhook',
  re: /(?:discord(?:app)?\.com|discord\.com)\/api\/webhooks\/\d+\/[\w-]{20,}/i,
  why: 'A hard-coded Discord webhook is the standard drop point for stolen data \u2014 no server needed.'
});

/* ───────────────────────────  RAT / BACKDOOR  ──────────────────────────── */

s('RAT-001', {
  name: 'Socket duplicated onto a shell',
  family: 'rat', tactic: 'c2', severity: 'critical', weight: 28,
  tags: ['remote-shell'], hint: 'dup2',
  re: /dup2\s*\(\s*[\w.]+(?:\.fileno\(\))?\s*,\s*[012]\s*\)|pty\.spawn\s*\(/,
  why: 'Duplicating a socket onto stdin/stdout and spawning a shell is a reverse shell, full stop.'
});

s('RAT-002', {
  name: 'Reverse shell one-liner',
  family: 'rat', tactic: 'c2', severity: 'critical', weight: 28,
  tags: ['remote-shell'], hint: 'sh',
  re: /\/dev\/tcp\/[\w.${}]+\/\d+|\bnc\s+(?:-[a-z]*e\s|-nlvp|-lvnp)|mkfifo[^\n]{0,40}\|\s*(?:ba)?sh|socat[^\n]{0,40}exec:/i,
  why: 'Shell redirection into /dev/tcp, `nc -e`, or a socat exec hands a live shell to a remote host.'
});

s('RAT-003', {
  name: 'PowerShell TCP client shell',
  family: 'rat', tactic: 'c2', severity: 'critical', weight: 28,
  tags: ['remote-shell'], hint: 'tcpclient',
  re: /System\.Net\.Sockets\.TCPClient|New-Object[^\n]{0,40}Sockets\.TcpClient/i,
  why: 'The standard PowerShell reverse-shell primitive.'
});

s('RAT-004', {
  name: 'Execution of network-supplied commands',
  family: 'rat', tactic: 'c2', severity: 'critical', weight: 24,
  tags: ['remote-exec'], hint: '(',
  re: /(?:subprocess\.(?:check_output|run|Popen|call)|os\.popen|os\.system|child_process\.exec\w*|Runtime\.getRuntime\(\)\.exec)\s*\(\s*(?:cmd|command|data|msg|payload|task|order|resp|response|body|text)\b/i,
  why: 'Running a command that arrived over the network is the defining behaviour of a backdoor.'
});

s('RAT-005', {
  name: 'Chat-platform bot exposing shell commands',
  family: 'rat', tactic: 'c2', severity: 'critical', weight: 24,
  tags: ['c2-beacon', 'remote-exec'], hint: 'command',
  re: /@(?:bot|client|tree)\.(?:command|slash_command)[^\n]{0,120}(?:shell|cmd|exec|screenshot|keylog|download|upload|persist)/i,
  why: 'A bot whose commands are shell/screenshot/download is a remote access trojan with a chat front-end.'
});

s('RAT-006', {
  name: 'Telegram bot command-and-control',
  family: 'rat', tactic: 'c2', severity: 'high', weight: 20,
  tags: ['c2-beacon'], hint: 'telegram',
  re: /api\.telegram\.org\/bot\d{6,}:[\w-]{30,}|sendMessage\?chat_id=/i,
  why: 'A hard-coded Telegram bot token plus chat id is the cheapest C2 and exfil channel available.'
});

s('RAT-007', {
  name: 'Poll-and-sleep beacon loop',
  family: 'rat', tactic: 'c2', severity: 'high', weight: 16,
  tags: ['c2-beacon'], hint: 'while', span: true,
  re: /while\s*(?:True|true|\(\s*(?:1|true)\s*\))\s*[:{][\s\S]{0,200}?(?:requests\.(?:get|post)|fetch\(|urlopen|axios|Invoke-WebRequest)[\s\S]{0,200}?(?:time\.sleep|sleep\(|Start-Sleep|setTimeout)/,
  why: 'An endless poll-then-sleep loop against a remote host is a C2 beacon.'
});

s('RAT-008', {
  name: 'Known RAT or C2 framework artefact',
  family: 'rat', tactic: 'c2', severity: 'critical', weight: 26,
  tags: ['c2-beacon', 'remote-shell'], hint: 'rat',
  re: /\b(?:meterpreter|cobalt\s?strike|covenant\s?grunt|sliver\s?implant|quasar\s?rat|njrat|asyncrat|dcrat|venom\s?rat|remcos|xworm|pupy\s?rat|havoc\s?demon)\b/i,
  why: 'Direct reference to a known implant or offensive C2 framework.'
});

s('RAT-009', {
  name: 'Tunnel exposing a local port publicly',
  family: 'rat', tactic: 'c2', severity: 'high', weight: 14,
  tags: ['c2-beacon'], hint: 'ngrok',
  re: /\d+\.tcp\.[a-z]{0,3}\.?ngrok\.io|ngrok\s+tcp\s+\d+|trycloudflare\.com|serveo\.net|localtunnel\.me/i,
  why: 'Tunnelling a local port to the internet is how an implant stays reachable behind NAT.'
});

s('RAT-010', {
  name: 'Deliberately hidden process window',
  family: 'rat', tactic: 'evasion', severity: 'medium', weight: 12,
  tags: ['anti-analysis'], hint: 'hidden',
  re: /CREATE_NO_WINDOW|SW_HIDE|WindowStyle\s+Hidden|-w\s+hidden|STARTF_USESHOWWINDOW/i,
  why: 'Suppressing every visible window keeps the user from noticing execution.'
});

s('RAT-011', {
  name: 'Remote desktop / screen streaming to operator',
  family: 'rat', tactic: 'collection', severity: 'high', weight: 16,
  tags: ['surveillance', 'remote-exec'], hint: 'screen',
  re: /(?:stream|send|upload)_?screen|remote_?desktop|vnc_?(?:server|start)|screen_?share_?loop/i,
  why: 'Continuous screen streaming to a controller is remote-access behaviour.'
});

/* ────────────────────────────  RANSOMWARE  ─────────────────────────────── */

s('RSM-001', {
  name: 'Recursive walk feeding an encryption routine',
  family: 'ransomware', tactic: 'impact', severity: 'critical', weight: 28,
  tags: ['bulk-encrypt'], hint: 'encrypt', span: true,
  re: /(?:os\.walk|walkdir|readdirSync|Directory\.GetFiles|filepath\.Walk)[\s\S]{0,300}?(?:encrypt|Fernet|AES\.new|createCipheriv|Rijndael|CryptEncrypt)/i,
  why: 'Walking the filesystem and encrypting each file found is the mechanical definition of ransomware.'
});

s('RSM-002', {
  name: 'Encrypt-then-overwrite of user files',
  family: 'ransomware', tactic: 'impact', severity: 'critical', weight: 26,
  tags: ['bulk-encrypt'], hint: 'encrypt', span: true,
  re: /encrypt(?:_file|File)?\s*\([^\n]{0,60}\)[\s\S]{0,160}?(?:os\.remove|unlink|fs\.rm|File\.Delete|shutil\.move)/i,
  why: 'Encrypting a file and then deleting or replacing the original leaves the victim no copy.'
});

s('RSM-003', {
  name: 'Ransom note authoring',
  family: 'ransomware', tactic: 'impact', severity: 'critical', weight: 26,
  tags: ['ransom-note'], hint: 'decrypt',
  re: /(?:your\s+files\s+(?:have\s+been|are)\s+encrypted|all\s+your\s+files\s+(?:are|have))|README[_-]?(?:DECRYPT|RESTORE)|HOW[_ -]?TO[_ -]?(?:DECRYPT|RECOVER)|DECRYPT[_-]?INSTRUCTIONS/i,
  why: 'A ransom note is written only by software that intends to hold data hostage.'
});

s('RSM-004', {
  name: 'Shadow copy and backup destruction',
  family: 'ransomware', tactic: 'impact', severity: 'critical', weight: 28,
  tags: ['shadow-delete', 'destructive'], hint: 'vssadmin',
  re: /vssadmin[^\n]{0,40}delete\s+shadows|wbadmin[^\n]{0,30}delete\s+catalog|Get-WmiObject[^\n]{0,30}Win32_Shadowcopy[^\n]{0,30}[Dd]elete/i,
  why: 'Deleting volume shadow copies exists only to stop a victim restoring their files.'
});

s('RSM-005', {
  name: 'Recovery environment sabotage',
  family: 'ransomware', tactic: 'impact', severity: 'critical', weight: 26,
  tags: ['recovery-kill', 'destructive'], hint: 'bcdedit',
  re: /bcdedit[^\n]{0,60}(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|reagentc\s+\/disable/i,
  why: 'Disabling Windows recovery blocks the victim\u2019s last local route back.'
});

s('RSM-006', {
  name: 'Mass extension rename to a ransom marker',
  family: 'ransomware', tactic: 'impact', severity: 'high', weight: 20,
  tags: ['extension-rename'], hint: 'rename',
  re: /(?:rename|os\.rename|renameSync|Move-Item)[^\n]{0,60}["'`]\.(?:locked|encrypted|crypt|enc|kudo|wnry|locky|ryuk|payx?)["'`]/i,
  why: 'Appending a marker extension to every encrypted file is how ransomware brands its victims.'
});

s('RSM-007', {
  name: 'Attacker-held key with no local escrow',
  family: 'ransomware', tactic: 'impact', severity: 'high', weight: 18,
  tags: ['bulk-encrypt'], hint: 'key', span: true,
  re: /(?:public_?key|PUBLIC_KEY|rsa_?pub)[\s\S]{0,200}?(?:encrypt(?:_key|ed_key)|session_?key)[\s\S]{0,200}?(?:post|send|upload|requests\.)/i,
  why: 'Encrypting the per-victim key under an attacker public key and shipping it is the ransomware key-escrow design.'
});

s('RSM-008', {
  name: 'Known ransomware family name',
  family: 'ransomware', tactic: 'impact', severity: 'critical', weight: 24,
  tags: ['ransom-note'], hint: 'ransom',
  re: /\b(?:lockbit|blackcat|alphv|conti\s?ransom|revil|sodinokibi|hive\s?ransom|wannacry|ryuk|djvu\s?stop|phobos\s?ransom)\b/i,
  why: 'Names a known ransomware family.'
});

/* ───────────────────────────  WIPER / DESTRUCTIVE  ─────────────────────── */

s('WIP-001', {
  name: 'Recursive delete of a filesystem root',
  family: 'wiper', tactic: 'impact', severity: 'critical', weight: 30,
  tags: ['destructive'], hint: 'rm',
  // Either a shell context, or an explicit exec call. A bare "rm -rf /" inside
  // an arbitrary string is test data far more often than it is an attack.
  re: /(?:^|[;&|]\s*|&&\s*)(?:sudo\s+)?rm\s+-[a-z]*[rR][a-z]*f?\s+(?:\/|~|\$HOME|\/home)(?:\s|$)|(?:system|exec\w*|popen|run|call|spawn\w*|Popen)\s*\(\s*["'`][^"'`\n]{0,24}rm\s+-[a-z]*[rR][a-z]*f?\s+[/~]|del\s+\/[fsq]\s+\/[fsq][^\n]{0,20}C:\\|Remove-Item[^\n]{0,40}C:\\[^\n]{0,10}-Recurse/i,
  why: 'Recursively deleting from the filesystem root destroys the machine, not a build directory.'
});

s('WIP-002', {
  name: 'Raw disk or MBR overwrite',
  family: 'wiper', tactic: 'impact', severity: 'critical', weight: 30,
  tags: ['destructive'], hint: 'dd',
  re: /dd\s+if=\/dev\/(?:zero|urandom)\s+of=\/dev\/[sh]d|\\\\\.\\PhysicalDrive\d|\bformat\s+[c-z]:\s*\/|mkfs\.\w+\s+\/dev\//i,
  why: 'Writing over a raw disk device or the MBR is unrecoverable destruction.'
});

s('WIP-003', {
  name: 'Fork bomb or resource exhaustion',
  family: 'wiper', tactic: 'impact', severity: 'high', weight: 20,
  tags: ['destructive'], hint: ':(',
  re: /:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:|while\s*\(\s*true\s*\)\s*\{\s*fork\(\)/,
  why: 'A fork bomb has one purpose: making the machine unusable.'
});

s('WIP-004', {
  name: 'System32 or critical path tampering',
  family: 'wiper', tactic: 'impact', severity: 'critical', weight: 24,
  tags: ['destructive'], hint: 'system32',
  re: /(?:del|Remove-Item|rmdir|shutil\.rmtree|rm\s+-rf)[^\n]{0,50}(?:System32|Windows\\\\?System|\/boot|\/etc)/i,
  why: 'Deleting from system directories bricks the OS.'
});

/* ────────────────────────────  CRYPTOMINER  ────────────────────────────── */

s('MIN-001', {
  name: 'Mining pool stratum endpoint',
  family: 'cryptominer', tactic: 'impact', severity: 'critical', weight: 28,
  tags: ['mining'], hint: 'stratum',
  // A real host is required: unit tests use the literal 'stratum+tcp://server:port'.
  re: /stratum\+(?:tcp|ssl):\/\/(?:[\w-]+\.)+[a-z]{2,}(?::\d+)?|stratum\+(?:tcp|ssl):\/\/(?:\d{1,3}\.){3}\d{1,3}|(?:pool|xmr|eth|rx)\.[\w.-]{2,30}:(?:3333|4444|5555|7777|14444|45700)\b/i,
  why: 'A stratum URL points at a mining pool. Nothing else speaks that protocol.'
});

s('MIN-002', {
  name: 'Miner binary or library reference',
  family: 'cryptominer', tactic: 'impact', severity: 'critical', weight: 26,
  tags: ['mining'], hint: 'miner',
  re: /\bxmrig\b|\bnbminer\b|\bphoenixminer\b|\bt-rex(?:miner)?\b|\bccminer\b|\bethminer\b|\bcpuminer\b|\blolminer\b|coinhive|cryptonight|randomx/i,
  why: 'Names a miner build or hashing algorithm implementation.'
});

s('MIN-003', {
  name: 'Wallet address passed as a mining user',
  family: 'cryptominer', tactic: 'impact', severity: 'high', weight: 22,
  tags: ['mining', 'wallet-address'], hint: '-u',
  re: /(?:--user|-u|--wallet|"user"\s*:)\s*["'`]?(?:4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})/,
  why: 'A wallet address in the miner user field is where the mined coin goes \u2014 that is the payload.'
});

s('MIN-004', {
  name: 'Miner throttling to stay unnoticed',
  family: 'cryptominer', tactic: 'evasion', severity: 'high', weight: 16,
  tags: ['mining', 'anti-analysis'], hint: 'cpu',
  re: /(?:--cpu-max-threads-hint|--max-cpu-usage|"max-cpu-usage")|(?:idle|afk)[^\n]{0,20}(?:mine|mining|hashrate)/i,
  why: 'Capping CPU or mining only while idle is done to keep the victim from noticing.'
});

/* ─────────────────────────────  CLIPPER  ───────────────────────────────── */

s('CLP-001', {
  name: 'Clipboard monitoring loop',
  family: 'clipper', tactic: 'collection', severity: 'high', weight: 18,
  tags: ['clipboard'], hint: 'clipboard',
  re: /pyperclip\.(?:paste|copy)|clipboard\.(?:read|write)Text|Get-Clipboard|Set-Clipboard|win32clipboard|clipboardy/i,
  why: 'Reading and writing the clipboard is the mechanism a clipper uses.'
});

s('CLP-002', {
  name: 'Wallet address substitution in clipboard',
  family: 'clipper', tactic: 'impact', severity: 'critical', weight: 28,
  tags: ['wallet-address'], hint: 'copy', span: true,
  re: /(?:paste\(\)|Get-Clipboard|readText\(\))[\s\S]{0,180}?(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,60}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{60,})[\s\S]{0,180}?(?:copy\(|Set-Clipboard|writeText\()/,
  why: 'Reading the clipboard, matching an address, then writing a different one back is a clipboard hijacker.'
});

s('CLP-003', {
  name: 'Hard-coded attacker wallet addresses',
  family: 'clipper', tactic: 'impact', severity: 'medium', weight: 12,
  tags: ['wallet-address'], hint: '0x',
  re: /["'`](?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{26,34}|T[A-Za-z1-9]{33})["'`]/,
  why: 'A literal wallet address in source is worth explaining \u2014 in a clipper it is the destination.'
});

/* ────────────────────────────  KEYLOGGER  ──────────────────────────────── */

s('KEY-001', {
  name: 'Global keyboard hook',
  family: 'keylogger', tactic: 'collection', severity: 'critical', weight: 26,
  tags: ['keylog'], hint: 'hook',
  re: /SetWindowsHookEx\w*\s*\(|WH_KEYBOARD_LL|pynput\.keyboard|keyboard\.(?:on_press|hook)\b|GetAsyncKeyState/i,
  why: 'A low-level global keyboard hook captures every keystroke system-wide.'
});

s('KEY-002', {
  name: 'Keystroke log written to disk',
  family: 'keylogger', tactic: 'collection', severity: 'high', weight: 20,
  tags: ['keylog'], hint: 'log',
  re: /(?:keylog|keystroke|keys?_?log)[\w]*\s*(?:=|\.write|\+=|\.append)|["'`][^"'`\n]*key(?:log|s)\.txt["'`]/i,
  why: 'An accumulating keystroke buffer that gets flushed to a file is a keylogger by construction.'
});

s('KEY-003', {
  name: 'Foreground window title tracking',
  family: 'keylogger', tactic: 'collection', severity: 'medium', weight: 10,
  // No 'keylog' tag on purpose: every GUI application on Windows calls
  // GetWindowText. This corroborates a keylogger, it never proves one.
  tags: ['surveillance'], hint: 'window',
  re: /GetForegroundWindow|GetWindowText\w*|active_?window[^\n]{0,20}title/i,
  why: 'Window titles are logged alongside keystrokes so the operator knows which app the typing went into.'
});

/* ────────────────────────  SPYWARE / SURVEILLANCE  ─────────────────────── */

s('SPY-001', {
  name: 'Screenshot capture',
  family: 'spyware', tactic: 'collection', severity: 'high', weight: 18,
  tags: ['surveillance'], hint: 'screen',
  re: /ImageGrab\.grab|mss\(\)|pyautogui\.screenshot|CopyFromScreen|desktopCapturer|screenshot-desktop|import\s+-window\s+root/i,
  why: 'Programmatic screen capture is surveillance unless the app is explicitly a screenshot tool.'
});

s('SPY-002', {
  name: 'Webcam capture',
  family: 'spyware', tactic: 'collection', severity: 'critical', weight: 22,
  tags: ['surveillance'], hint: 'cam',
  re: /VideoCapture\s*\(\s*0\s*\)|cv2\.VideoCapture|getUserMedia\s*\([^\n]{0,40}video|ffmpeg[^\n]{0,40}(?:dshow|v4l2)[^\n]{0,40}video/i,
  why: 'Opening the camera without a user-facing reason is spyware behaviour.'
});

s('SPY-003', {
  name: 'Microphone recording',
  family: 'spyware', tactic: 'collection', severity: 'critical', weight: 22,
  tags: ['surveillance'], hint: 'audio',
  re: /sounddevice\.rec|pyaudio\.PyAudio|waveInOpen|getUserMedia\s*\([^\n]{0,40}audio|record_?(?:mic|audio)\b/i,
  why: 'Silent microphone capture is eavesdropping.'
});

s('SPY-004', {
  name: 'Geolocation / IP profiling of the victim',
  family: 'spyware', tactic: 'discovery', severity: 'medium', weight: 14,
  tags: ['surveillance'], hint: 'ip',
  re: /ip-?api\.com|ipinfo\.io|ipify\.org|geoplugin|freegeoip|wtfismyip/i,
  why: 'Fingerprinting the victim\u2019s public IP and location is standard first-run reporting for implants.'
});

s('SPY-005', {
  name: 'Host fingerprint collection bundle',
  family: 'spyware', tactic: 'discovery', severity: 'medium', weight: 14,
  tags: ['surveillance'], hint: 'platform', span: true,
  re: /(?:platform\.(?:node|system|processor)|os\.hostname|getpass\.getuser|os\.userInfo)[\s\S]{0,200}?(?:post|send|webhook|requests\.|fetch\()/i,
  why: 'Machine name, user and OS bundled into an outbound request is victim registration.'
});

/* ────────────────────────────  LOADER / DROPPER  ───────────────────────── */

s('LDR-001', {
  name: 'Download piped straight into a shell',
  family: 'loader', tactic: 'execution', severity: 'critical', weight: 30,
  tags: ['remote-payload', 'exec-payload'], hint: 'curl',
  re: /(?:curl|wget)\s+[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|s)?sh\b|iwr\s+[^\n|]{0,80}\|\s*iex|Invoke-WebRequest[^\n]{0,80}\|\s*Invoke-Expression/i,
  why: 'Piping a downloaded script directly into a shell executes whatever the server decides to send, unreviewed.'
});

s('LDR-002', {
  name: 'PowerShell download-and-execute',
  family: 'loader', tactic: 'execution', severity: 'critical', weight: 28,
  tags: ['remote-payload', 'memory-exec'], hint: 'downloadstring',
  re: /DownloadString\s*\(|DownloadFile\s*\(|Net\.WebClient[^\n]{0,60}Download|IEX\s*\(\s*New-Object/i,
  why: 'WebClient download fed to IEX runs remote code in memory with nothing written to disk.'
});

s('LDR-003', {
  name: 'Remote payload written to disk and executed',
  family: 'loader', tactic: 'execution', severity: 'critical', weight: 26,
  tags: ['remote-payload', 'write-exec'], hint: 'write', span: true,
  re: /(?:urlretrieve|requests\.get|fetch\(|DownloadFile|WebClient)[\s\S]{0,260}?(?:\.write|writeFileSync|open\([^\n]{0,40}["'`]wb)[\s\S]{0,200}?(?:startfile|Popen|exec|Start-Process|spawn|system\()/i,
  why: 'Fetch, write, run \u2014 the three-step dropper sequence.'
});

s('LDR-004', {
  name: 'Payload fetched from a paste or file-drop host',
  family: 'loader', tactic: 'c2', severity: 'high', weight: 20,
  tags: ['remote-payload'], hint: 'http',
  re: /(?:pastebin\.com\/raw|hastebin|paste\.ee|ghostbin|transfer\.sh|anonfiles|gofile\.io|file\.io|bashupload|0x0\.st|cdn\.discordapp\.com\/attachments)/i,
  why: 'Second stages are hosted on paste and file-drop sites because they are free and disposable.'
});

s('LDR-005', {
  name: 'Shellcode injected into allocated memory',
  family: 'loader', tactic: 'execution', severity: 'critical', weight: 30,
  tags: ['memory-exec', 'proc-inject'], hint: 'virtualalloc',
  re: /VirtualAlloc(?:Ex)?\s*\(|WriteProcessMemory\s*\(|CreateRemoteThread\s*\(|NtMapViewOfSection|mmap\([^\n]{0,60}PROT_EXEC/i,
  why: 'Allocating RWX memory and starting a thread on it is shellcode execution.'
});

s('LDR-006', {
  name: 'Shellcode byte array',
  family: 'loader', tactic: 'execution', severity: 'critical', weight: 26,
  tags: ['memory-exec'], hint: '\\x',
  re: /(?:\\x[0-9a-fA-F]{2}){20,}|(?:0x[0-9a-fA-F]{2}\s*,\s*){24,}/,
  why: 'A long raw byte blob in source is almost always shellcode or an embedded binary.'
});

s('LDR-007', {
  name: 'In-memory .NET assembly loading',
  family: 'loader', tactic: 'evasion', severity: 'critical', weight: 26,
  tags: ['memory-exec'], hint: 'load',
  re: /\[Reflection\.Assembly\]::Load|Assembly\.Load\s*\(\s*\[?(?:byte|Convert)/i,
  why: 'Loading an assembly from a byte array leaves no file for a scanner to inspect.'
});

s('LDR-008', {
  name: 'Dynamic import of a remotely fetched module',
  family: 'loader', tactic: 'execution', severity: 'high', weight: 22,
  tags: ['remote-payload', 'exec-payload'], hint: 'eval',
  re: /eval\s*\(\s*(?:await\s*)?(?:fetch|require\(['"`]https?|request|urlopen|res(?:ponse)?\.(?:text|body|data))/i,
  why: 'Evaluating a network response is remote code execution by design.'
});

/* ─────────────────────────  BOTNET / DDOS  ─────────────────────────────── */

s('BOT-001', {
  name: 'Packet flood loop',
  family: 'botnet', tactic: 'impact', severity: 'critical', weight: 24,
  tags: ['flood'], hint: 'flood',
  re: /(?:udp|tcp|syn|http|slowloris)_?flood|while[^\n]{0,40}(?:sendto|sock\.send)\s*\(|def\s+(?:attack|flood|ddos)\s*\(/i,
  why: 'Unbounded packet sending in a loop is a denial-of-service payload.'
});

s('BOT-002', {
  name: 'Spoofed source or raw socket flooding',
  family: 'botnet', tactic: 'impact', severity: 'critical', weight: 24,
  tags: ['flood'], hint: 'raw',
  re: /SOCK_RAW|IPPROTO_RAW|IP_HDRINCL|scapy[^\n]{0,40}(?:send|sr1)\s*\(/i,
  why: 'Raw sockets with a custom IP header are used to spoof the source of flood traffic.'
});

s('BOT-003', {
  name: 'Botnet IRC / worker registration',
  family: 'botnet', tactic: 'c2', severity: 'high', weight: 20,
  tags: ['bot-c2'], hint: 'bot',
  re: /\b(?:mirai|qbot|gafgyt|bashlite|kaiten)\b|JOIN\s+#[\w-]{2,20}[^\n]{0,20}(?:bot|zombie)|register_?bot\s*\(/i,
  why: 'Registering the host as a worker in a controlled swarm.'
});

/* ─────────────────────────  WORM / SPREADER  ──────────────────────────── */

s('WRM-001', {
  name: 'Self-copy onto removable drives',
  family: 'worm', tactic: 'lateral', severity: 'critical', weight: 26,
  tags: ['self-spread'], hint: 'drive',
  re: /GetLogicalDrives|DRIVE_REMOVABLE|win32file\.GetDriveType|(?:copy|shutil\.copy)[^\n]{0,60}(?:[D-Z]:\\|\/media\/|\/Volumes\/)/i,
  why: 'Copying itself to every removable drive is USB worm propagation.'
});

s('WRM-002', {
  name: 'autorun.inf authoring',
  family: 'worm', tactic: 'lateral', severity: 'critical', weight: 24,
  tags: ['self-spread'], hint: 'autorun',
  re: /autorun\.inf|\[autorun\]/i,
  why: 'autorun.inf exists to make removable media execute code on insertion.'
});

s('WRM-003', {
  name: 'Self-replication using own source path',
  family: 'worm', tactic: 'lateral', severity: 'high', weight: 20,
  tags: ['self-spread'], hint: 'argv[0]', span: true,
  re: /(?:sys\.argv\[0\]|__file__|process\.execPath|Assembly\.GetExecutingAssembly\(\)\.Location)[\s\S]{0,140}?(?:copy|copyfile|CopyFileSync|File\.Copy|shutil\.copy)/i,
  why: 'Reading its own image path in order to copy it elsewhere is self-replication.'
});

s('WRM-004', {
  name: 'Contact-list or share-based propagation',
  family: 'worm', tactic: 'lateral', severity: 'high', weight: 20,
  tags: ['self-spread'], hint: 'send',
  // The underscore/camel boundary is required: socket.sendall() is not a worm.
  re: /(?:send|spam)_(?:to_)?(?:all|friends|contacts|guilds|servers)\b|(?:send|spam)To(?:All|Friends|Contacts|Guilds|Servers)\b|for\s+\w+\s+in[^\n]{0,30}(?:friends|contacts|guilds)[^\n]{0,40}send/i,
  why: 'Mailing itself to everyone the victim knows is how a worm reaches the next host.'
});

/* ───────────────────────  ROOTKIT / EVASION  ───────────────────────────── */

s('EVA-001', {
  name: 'Defender exclusion or shutdown',
  family: 'rootkit', tactic: 'evasion', severity: 'critical', weight: 28,
  tags: ['av-tamper'], hint: 'defender',
  re: /Add-MpPreference[^\n]{0,60}Exclusion|Set-MpPreference[^\n]{0,60}Disable\w*|DisableRealtimeMonitoring|Uninstall-WindowsFeature[^\n]{0,30}Defender|net\s+stop\s+windefend/i,
  why: 'Excluding itself from, or disabling, the endpoint AV is a defence-evasion action.'
});

s('EVA-002', {
  name: 'AMSI bypass',
  family: 'rootkit', tactic: 'evasion', severity: 'critical', weight: 30,
  tags: ['amsi'], hint: 'amsi',
  re: /amsiInitFailed|AmsiScanBuffer|amsi\.dll|System\.Management\.Automation\.AmsiUtils/i,
  why: 'Patching AMSI blinds the runtime script scanner. There is no defensive reason to do it.'
});

s('EVA-003', {
  name: 'ETW / event log tampering',
  family: 'rootkit', tactic: 'evasion', severity: 'critical', weight: 26,
  tags: ['av-tamper'], hint: 'etw',
  re: /EtwEventWrite|wevtutil\s+cl|Clear-EventLog|auditpol\s+\/set[^\n]{0,40}disable/i,
  why: 'Silencing or clearing the event log destroys the forensic trail.'
});

s('EVA-004', {
  name: 'Process hollowing / injection sequence',
  family: 'rootkit', tactic: 'evasion', severity: 'critical', weight: 28,
  tags: ['hollowing', 'proc-inject'], hint: 'thread',
  re: /NtUnmapViewOfSection|SetThreadContext|QueueUserAPC|ResumeThread\s*\([^\n]{0,40}\)|CREATE_SUSPENDED/i,
  why: 'Creating a suspended process, swapping its image and resuming it is process hollowing.'
});

s('EVA-005', {
  name: 'Sandbox and VM detection',
  family: 'rootkit', tactic: 'evasion', severity: 'high', weight: 22,
  tags: ['anti-analysis'], hint: 'vbox',
  re: /\b(?:vboxservice|vmtoolsd|vmware|virtualbox|qemu|sandboxie|cuckoo|wine_get_version)\b|IsDebuggerPresent|CheckRemoteDebuggerPresent|\bsbiedll\b/i,
  why: 'Refusing to run inside analysis environments is behaviour only malware needs.'
});

s('EVA-006', {
  name: 'Analysis tool process killing',
  family: 'rootkit', tactic: 'evasion', severity: 'high', weight: 22,
  tags: ['anti-analysis', 'av-tamper'], hint: 'taskkill',
  re: /(?:taskkill|Stop-Process|os\.kill|pkill)[^\n]{0,60}(?:procmon|wireshark|processhacker|x64dbg|ollydbg|ida64|fiddler|httpdebugger|tcpview)/i,
  why: 'Killing debuggers and network monitors on sight is anti-analysis.'
});

s('EVA-007', {
  name: 'Unsigned driver load / kernel mapping',
  family: 'rootkit', tactic: 'privesc', severity: 'critical', weight: 26,
  tags: ['kernel-driver'], hint: 'driver',
  re: /NtLoadDriver|\bkdmapper\b|\bcapcom\.sys\b|\biqvw64e\.sys\b|\bdbutil_2_3\.sys\b|testsigning\s+on|bcdedit[^\n]{0,40}nointegritychecks/i,
  why: 'Mapping an unsigned or known-vulnerable driver is how a rootkit reaches kernel mode.'
});

s('EVA-008', {
  name: 'UAC bypass technique',
  family: 'rootkit', tactic: 'privesc', severity: 'critical', weight: 24,
  tags: ['av-tamper'], hint: 'uac',
  re: /fodhelper|computerdefaults|eventvwr[^\n]{0,30}(?:hijack|bypass)|sdclt[^\n]{0,30}bypass|ms-settings\\\\?shell\\\\?open/i,
  why: 'These auto-elevating binaries are only referenced when bypassing UAC.'
});

s('EVA-009', {
  name: 'File attribute hiding or timestomping',
  family: 'rootkit', tactic: 'evasion', severity: 'medium', weight: 14,
  tags: ['anti-analysis'], hint: 'attrib',
  re: /attrib\s+\+[hs]|FILE_ATTRIBUTE_HIDDEN|SetFileTime\s*\(|os\.utime\s*\([^\n]{0,40}\)|touch\s+-[amt]\s/i,
  why: 'Hiding the file or faking its timestamps is done to survive a manual look.'
});

/* ───────────────────────────  PERSISTENCE  ─────────────────────────────── */

s('PER-001', {
  name: 'Registry Run key persistence',
  family: 'persistence', tactic: 'persistence', severity: 'high', weight: 22,
  tags: ['persist'], hint: 'currentversion\\run',
  re: /CurrentVersion\\+Run(?:Once)?|HKCU[^\n]{0,40}\\Run\b|reg\s+add[^\n]{0,60}\\Run\b/i,
  why: 'Writing a Run key makes the program start with every login.'
});

s('PER-002', {
  name: 'Startup folder drop',
  family: 'persistence', tactic: 'persistence', severity: 'high', weight: 20,
  tags: ['persist'], hint: 'startup',
  re: /Start\s?Menu[\\/]Programs[\\/]Startup|shell:startup|Microsoft[\\/]Windows[\\/]Start Menu/i,
  why: 'A file dropped in the Startup folder runs at every login.'
});

s('PER-003', {
  name: 'Scheduled task or cron installation',
  family: 'persistence', tactic: 'persistence', severity: 'high', weight: 20,
  tags: ['persist'], hint: 'schtasks',
  re: /schtasks\s+\/create|Register-ScheduledTask|crontab\s+-|\/etc\/cron\.[a-z]+\/|@reboot\s/i,
  why: 'Scheduling itself to re-run is persistence.'
});

s('PER-004', {
  name: 'Service, systemd unit or launch agent install',
  family: 'persistence', tactic: 'persistence', severity: 'high', weight: 20,
  tags: ['persist'], hint: 'service',
  re: /sc\s+create\s|New-Service|systemctl\s+enable|\/etc\/systemd\/system\/[\w.-]+\.service|Library\/LaunchAgents|launchctl\s+load/i,
  why: 'Installing itself as a service or agent survives reboot with elevated context.'
});

s('PER-005', {
  name: 'Shell profile persistence',
  family: 'persistence', tactic: 'persistence', severity: 'medium', weight: 16,
  tags: ['persist'], hint: 'bashrc',
  re: />>\s*~?\/?\.(?:bashrc|zshrc|bash_profile|profile)\b|\.bashrc["'`]\s*,\s*["'`]a/i,
  why: 'Appending to a shell profile re-executes the payload in every new terminal.'
});

s('PER-006', {
  name: 'WMI event subscription persistence',
  family: 'persistence', tactic: 'persistence', severity: 'critical', weight: 24,
  tags: ['persist'], hint: 'wmi',
  re: /__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding/i,
  why: 'WMI event subscriptions are fileless persistence that survives most cleanups.'
});

/* ──────────────────────────  SUPPLY CHAIN  ─────────────────────────────── */

s('SUP-001', {
  name: 'Install lifecycle hook executes code',
  family: 'supplychain', tactic: 'execution', severity: 'critical', weight: 24,
  tags: ['install-hook'], hint: 'install',
  re: /"(?:pre|post)install"\s*:\s*"(?!(?:echo|exit|true|node-gyp\b|husky\b|patch-package\b))[^"]{4,}"/i,
  why: 'npm install hooks run automatically on `npm i`, before anyone reads the code.'
});

s('SUP-002', {
  name: 'Install hook reaching the network',
  family: 'supplychain', tactic: 'execution', severity: 'critical', weight: 30,
  tags: ['install-hook', 'remote-payload'], hint: 'install',
  re: /"(?:pre|post)install"\s*:\s*"[^"]{0,200}(?:curl|wget|Invoke-WebRequest|powershell|https?:\/\/|base64|eval)[^"]{0,200}"/i,
  why: 'An install hook that downloads or evaluates code is the classic npm supply-chain attack.'
});

s('SUP-003', {
  name: 'setup.py executing at build time',
  family: 'supplychain', tactic: 'execution', severity: 'critical', weight: 24,
  tags: ['install-hook'], hint: 'install', ext: ['py'],
  re: /class\s+\w*(?:Install|Develop|Egg)\w*\s*\([^\n]{0,40}\)\s*:|cmdclass\s*=\s*\{/,
  why: 'Overriding the install command runs attacker code during `pip install`.'
});

s('SUP-004', {
  name: 'CI workflow exfiltrating repository secrets',
  family: 'supplychain', tactic: 'exfiltration', severity: 'critical', weight: 26,
  tags: ['install-hook'], hint: 'secrets',
  re: /\$\{\{\s*(?:secrets|toJSON\(secrets)[^\n]{0,60}\}\}[^\n]{0,80}(?:curl|wget|nc\s|https?:\/\/)|toJSON\(secrets\)/i,
  why: 'A workflow that pipes repository secrets to an external host is stealing them.'
});

/* Dependency-source analysis lives in core/manifest.js (PKG-005) instead of a
   regex: it needs to know which JSON keys are actually dependency blocks.
   A line-level rule here matched "homepage" and funding URLs. */

/* ───────────────────────  OBFUSCATION / PACKER  ────────────────────────── */

s('OBF-001', {
  name: 'eval of decoded data',
  family: 'packer', tactic: 'evasion', severity: 'critical', weight: 26,
  tags: ['obfuscation', 'exec-payload'], hint: 'eval',
  re: /eval\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|unescape|decodeURIComponent|zlib|gzip|marshal\.loads|pickle\.loads|lzma)/i,
  why: 'Decoding a blob and evaluating it hides the real payload from review and from scanners.'
});

s('OBF-002', {
  name: 'exec of decoded data',
  family: 'packer', tactic: 'evasion', severity: 'critical', weight: 26,
  tags: ['obfuscation', 'exec-payload'], hint: 'exec',
  re: /exec\s*\(\s*(?:__import__\(["'`]base64|base64\.|bytes\.fromhex|zlib\.decompress|marshal\.loads|codecs\.decode|lzma\.decompress)/i,
  why: 'Python `exec` over decoded bytes is the standard packed-payload pattern.'
});

s('OBF-003', {
  name: 'PowerShell encoded command',
  family: 'packer', tactic: 'evasion', severity: 'critical', weight: 26,
  tags: ['obfuscation', 'exec-payload'], hint: 'powershell',
  re: /powershell[^\n]{0,60}-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}|FromBase64String\s*\(/i,
  why: '-EncodedCommand exists to keep the real command out of logs and out of sight.'
});

s('OBF-004', {
  name: 'Long embedded base64 blob',
  family: 'packer', tactic: 'evasion', severity: 'high', weight: 14,
  tags: ['obfuscation'], hint: '"',
  re: /["'`][A-Za-z0-9+\/]{400,}={0,2}["'`]/,
  why: 'A very long base64 literal usually is the payload rather than data.'
});

s('OBF-005', {
  name: 'Character-code array reassembly',
  family: 'packer', tactic: 'evasion', severity: 'high', weight: 18,
  tags: ['obfuscation'], hint: 'chr',
  re: /(?:String\.fromCharCode|chr\(\s*\d+\s*\)\s*\+){6,}|(?:chr\(\d{2,3}\)\s*\+\s*){6,}|\[\s*(?:\d{2,3}\s*,\s*){20,}/,
  why: 'Rebuilding strings from character codes hides them from a reader and from grep.'
});

s('OBF-006', {
  name: 'Known JavaScript obfuscator output',
  family: 'packer', tactic: 'evasion', severity: 'high', weight: 20,
  tags: ['obfuscation'], hint: '_0x',
  re: /_0x[a-f0-9]{4,6}\s*[=(\[]|var\s+_0x[a-f0-9]{4}\s*=\s*\[|\bjsjiami\b|obfuscator\.io/i,
  why: 'The `_0x` hex-identifier style is the fingerprint of javascript-obfuscator.'
});

s('OBF-007', {
  name: 'Python packer / protector artefact',
  family: 'packer', tactic: 'evasion', severity: 'high', weight: 20,
  tags: ['obfuscation'], hint: 'pyarmor',
  re: /pyarmor|pyobfuscate|__pyarmor__|__pyminifier|hyperion|\bUPX!\b|py2exe|PyInstaller/i,
  why: 'Protectors and packers are used to stop anyone reading what the program actually does.'
});

s('OBF-008', {
  name: 'JSFuck / symbol-only encoding',
  family: 'packer', tactic: 'evasion', severity: 'high', weight: 20,
  tags: ['obfuscation'], hint: '[]',
  re: /(?:\[\]\[[^\]]{0,10}\]\s*\+\s*){4,}|\(!\[\]\+\[\]\)|\[\+!\+\[\]\]/,
  why: 'Symbol-only JavaScript encoding exists purely to defeat inspection.'
});

s('OBF-009', {
  name: 'Zero-width or bidi characters in source',
  family: 'packer', tactic: 'evasion', severity: 'critical', weight: 24,
  tags: ['obfuscation'], hint: '\u200b',
  re: /[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/,
  why: 'Invisible or direction-override characters can make source read differently than it executes (trojan source).'
});

/* ─────────────────────────  HACKTOOL / RISKWARE  ───────────────────────── */

s('HTL-001', {
  name: 'Cross-process memory read/write',
  family: 'hacktool', tactic: 'execution', severity: 'high', weight: 20,
  tags: ['proc-inject'], hint: 'process',
  re: /OpenProcess\s*\(|ReadProcessMemory\s*\(|process_vm_(?:readv|writev)|task_for_pid/i,
  why: 'Reading or writing another process\u2019 memory is debugger territory; outside a debugger it is tampering.'
});

s('HTL-002', {
  name: 'DLL injection',
  family: 'hacktool', tactic: 'execution', severity: 'critical', weight: 24,
  tags: ['proc-inject'], hint: 'inject',
  re: /LoadLibrary\w*\s*\([^\n]{0,60}\)|inject(?:or|_dll|Dll)\b|SetWindowsHookEx[^\n]{0,40}(?:hMod|hInstance)|LD_PRELOAD/i,
  why: 'Loading a library into a process you do not own is injection.'
});

s('HTL-003', {
  name: 'Graphics API hooking',
  family: 'hacktool', tactic: 'evasion', severity: 'medium', weight: 14,
  tags: ['hacktool-feature'], hint: 'hook',
  re: /(?:Present|EndScene|SwapBuffers|vkQueuePresentKHR)\s*(?:Hook|_hook)|MinHook|Detours|DetourAttach/i,
  why: 'Hooking the render loop is how overlays and visual cheats draw themselves.'
});

s('HTL-004', {
  name: 'Credential brute-force or cracking tooling',
  family: 'hacktool', tactic: 'credaccess', severity: 'high', weight: 18,
  tags: ['hacktool-feature'], hint: 'brute',
  re: /\b(?:brute\s?force|bruteforce|password_?list|wordlist|hashcat|john\s+the\s+ripper|hydra\s+-l)\b/i,
  why: 'Bulk credential guessing tooling. Legitimate in a pentest repo, hostile anywhere else.'
});

s('HTL-005', {
  name: 'Mimikatz / LSASS credential dumping',
  family: 'hacktool', tactic: 'credaccess', severity: 'critical', weight: 28,
  tags: ['hacktool-feature'], hint: 'lsass',
  re: /\bmimikatz\b|sekurlsa::|lsadump::|MiniDumpWriteDump|comsvcs\.dll[^\n]{0,30}MiniDump|procdump[^\n]{0,30}lsass/i,
  why: 'Dumping LSASS extracts every credential in memory.'
});

/* ────────────────────────────  PHISHING  ──────────────────────────────── */

s('PHI-001', {
  name: 'Cloned brand login form',
  family: 'phishing', tactic: 'credaccess', severity: 'critical', weight: 24,
  tags: ['fake-login'], hint: 'password', ext: ['html', 'htm', 'php', 'jsx', 'tsx', 'vue'],
  re: /<input[^>]{0,120}type=["']password["'][^>]{0,200}>[\s\S]{0,400}?(?:steam|paypal|microsoft|apple\s?id|facebook|instagram|roblox|binance|coinbase|metamask)/i,
  why: 'A password field on a page dressed as someone else\u2019s brand is a credential harvester.'
});

s('PHI-002', {
  name: 'Credentials POSTed to a third-party collector',
  family: 'phishing', tactic: 'exfiltration', severity: 'critical', weight: 24,
  tags: ['fake-login'], hint: 'password',
  re: /(?:password|passwd|pwd)["'`]?\s*[:=][^\n]{0,60}(?:webhook|telegram|bot\d|https?:\/\/(?!localhost|127\.0\.0\.1))/i,
  why: 'Typed passwords being sent to an unrelated endpoint is harvesting.'
});

s('PHI-003', {
  name: 'Seed phrase / recovery phrase capture',
  family: 'phishing', tactic: 'credaccess', severity: 'critical', weight: 28,
  tags: ['fake-login', 'wallet-theft'], hint: 'phrase',
  re: /(?:seed|mnemonic|recovery|secret)[\s_-]?phrase|12[\s-]?word|24[\s-]?word[^\n]{0,20}phrase|bip39[^\n]{0,30}(?:input|form|submit)/i,
  why: 'Collecting a recovery phrase gives complete, irreversible control of a wallet.'
});

/* ─────────────────────────────  ADWARE  ───────────────────────────────── */

s('ADW-001', {
  name: 'Browser homepage / search hijack',
  family: 'adware', tactic: 'impact', severity: 'medium', weight: 14,
  tags: ['adware'], hint: 'search',
  re: /(?:homepage|startup_?url|default_?search|search_?provider)\s*[:=][^\n]{0,60}https?:\/\//i,
  why: 'Rewriting the homepage or default search engine is browser hijacking.'
});

s('ADW-002', {
  name: 'Ad or affiliate injection into pages',
  family: 'adware', tactic: 'impact', severity: 'medium', weight: 14,
  tags: ['adware'], hint: 'inject',
  re: /(?:inject|append)(?:_?ad|Ad|Script)\b|document\.write\s*\(\s*['"`]<script[^\n]{0,60}(?:ads?|banner|popunder)|ref(?:erral)?[_-]?(?:code|id)\s*=\s*["'`]\w{4,}/i,
  why: 'Injecting ad or affiliate tags into pages the user visits monetises them without consent.'
});

s('ADW-003', {
  name: 'Silent bundled installer execution',
  family: 'adware', tactic: 'execution', severity: 'medium', weight: 14,
  tags: ['adware'], hint: 'silent',
  re: /\/(?:silent|verysilent|quiet|qn)\b|msiexec[^\n]{0,40}\/q|Start-Process[^\n]{0,60}-(?:Wait\s+)?-?(?:WindowStyle\s+Hidden|ArgumentList[^\n]{0,20}\/S)/i,
  why: 'Installing extra software silently is the defining PUP behaviour.'
});

/* ───────────────────  GENERIC EXFIL / NETWORK SIGNALS  ─────────────────── */

s('NET-001', {
  name: 'Hard-coded raw IP endpoint',
  family: 'rat', tactic: 'c2', severity: 'medium', weight: 10,
  tags: ['c2-beacon'], hint: 'http',
  re: /https?:\/\/(?!127\.0\.0\.1|0\.0\.0\.0|localhost|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/,
  why: 'A literal public IP endpoint sidesteps DNS and domain reputation \u2014 common for C2.'
});

s('NET-002', {
  name: 'Onion / darknet endpoint',
  family: 'rat', tactic: 'c2', severity: 'high', weight: 20,
  tags: ['c2-beacon'], hint: '.onion',
  re: /[a-z2-7]{16,56}\.onion/i,
  why: 'Hidden-service C2 endpoints are chosen to be untraceable.'
});

s('NET-003', {
  name: 'Certificate validation disabled',
  family: 'rootkit', tactic: 'evasion', severity: 'medium', weight: 12,
  tags: ['anti-analysis'], hint: 'verify',
  re: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0|ServerCertificateValidationCallback\s*=/i,
  why: 'Turning off TLS validation lets a self-signed C2 or an intercepting proxy work quietly.'
});

s('NET-004', {
  name: 'DNS tunnelling / DoH exfil channel',
  family: 'rat', tactic: 'exfiltration', severity: 'high', weight: 18,
  tags: ['c2-beacon'], hint: 'dns',
  re: /dns(?:cat|tunnel|steal)|dns-?query\?name=|TXT\s+record[^\n]{0,30}(?:decode|base64)|iodine\s+-/i,
  why: 'DNS tunnelling smuggles data out of networks that block ordinary egress.'
});

module.exports = { SIGNATURES: R };
