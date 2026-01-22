# NullSec SSHBrute - SSH Authentication Tester
# Nim security tool demonstrating:
#   - Async/await for concurrent connections
#   - Result types for error handling
#   - Option types for null safety
#   - Distinct types for type safety
#   - Memory safety with ARC
#
# Author: bad-antics
# License: MIT

import std/[asyncdispatch, asyncnet, strutils, strformat, os, times, terminal]
import std/[parseopt, tables, sets, locks]

const VERSION = "1.0.0"

type
  Severity = enum
    Critical, High, Medium, Low, Info

  Credential = object
    username: string
    password: string

  AttemptResult = object
    credential: Credential
    success: bool
    error: string
    duration: float

  Stats = object
    attempts: int
    successes: int
    failures: int
    errors: int
    startTime: float

  Config = object
    host: string
    port: int
    userlist: seq[string]
    passlist: seq[string]
    timeout: int
    concurrency: int
    verbose: bool
    jsonOutput: bool
    delay: int

# Colors
const
  Reset = "\e[0m"
  Red = "\e[31m"
  Green = "\e[32m"
  Yellow = "\e[33m"
  Cyan = "\e[36m"
  Gray = "\e[90m"

# Default credentials to test
const DefaultUsers = @[
  "root", "admin", "user", "test", "guest", "oracle", "postgres",
  "mysql", "ftp", "www-data", "nobody", "daemon", "bin", "sys"
]

const DefaultPasswords = @[
  "password", "123456", "admin", "root", "toor", "pass", "test",
  "guest", "changeme", "default", "letmein", "welcome", "password123",
  "admin123", "root123", "qwerty", "12345678", "abc123", "monkey"
]

proc printBanner() =
  echo """

╔══════════════════════════════════════════════════════════════════╗
║          NullSec SSHBrute - SSH Authentication Tester            ║
╚══════════════════════════════════════════════════════════════════╝
"""

proc printHelp() =
  printBanner()
  echo """
USAGE:
    sshbrute [OPTIONS] -t <TARGET>

OPTIONS:
    -t, --target HOST     Target host
    -p, --port PORT       SSH port (default: 22)
    -U, --userlist FILE   Username wordlist
    -P, --passlist FILE   Password wordlist
    -u, --user USER       Single username
    -w, --pass PASS       Single password
    -c, --concurrency N   Concurrent connections (default: 10)
    -T, --timeout SEC     Connection timeout (default: 5)
    -d, --delay MS        Delay between attempts (default: 0)
    -v, --verbose         Verbose output
    -j, --json            JSON output
    -h, --help            Show this help

EXAMPLES:
    sshbrute -t 192.168.1.1
    sshbrute -t target.com -U users.txt -P passwords.txt
    sshbrute -t 10.0.0.1 -u root -P rockyou.txt -c 20
"""

proc loadWordlist(path: string): seq[string] =
  result = @[]
  if not fileExists(path):
    echo &"Warning: File not found: {path}"
    return
  
  for line in lines(path):
    let trimmed = line.strip()
    if trimmed.len > 0 and not trimmed.startsWith("#"):
      result.add(trimmed)

proc formatDuration(secs: float): string =
  if secs < 60:
    return &"{secs:.1f}s"
  elif secs < 3600:
    return &"{secs / 60:.1f}m"
  else:
    return &"{secs / 3600:.1f}h"

# Simple SSH banner grab to check if service is alive
proc checkSSH(host: string, port: int, timeout: int): Future[bool] {.async.} =
  try:
    let sock = newAsyncSocket()
    await sock.connect(host, Port(port))
    
    # Read SSH banner
    let banner = await sock.recvLine()
    sock.close()
    
    return banner.startsWith("SSH-")
  except:
    return false

# Attempt SSH connection (simplified - real implementation would use libssh)
proc tryCredential(host: string, port: int, cred: Credential, 
                   timeout: int): Future[AttemptResult] {.async.} =
  let startTime = epochTime()
  var result = AttemptResult(
    credential: cred,
    success: false,
    error: "",
    duration: 0.0
  )
  
  try:
    let sock = newAsyncSocket()
    
    # Set timeout
    # await sock.connect(host, Port(port))
    # In real implementation, would perform SSH authentication here
    # Using libssh2 or similar library
    
    # Simulate connection attempt
    await sleepAsync(50)  # Simulated delay
    
    # For demonstration - would check actual auth result
    result.success = false
    result.error = "Auth failed"
    
  except CatchableError as e:
    result.error = e.msg
  
  result.duration = epochTime() - startTime
  return result

proc printResult(res: AttemptResult, verbose: bool) =
  if res.success:
    echo &"{Green}[+] SUCCESS{Reset} {res.credential.username}:{res.credential.password}"
  elif verbose:
    echo &"{Gray}[-]{Reset} {res.credential.username}:{res.credential.password} - {res.error}"

proc printJsonResult(res: AttemptResult) =
  let status = if res.success: "success" else: "failed"
  echo &"""{{ "user": "{res.credential.username}", "pass": "{res.credential.password}", "status": "{status}" }}"""

proc printStats(stats: Stats, elapsed: float) =
  echo ""
  echo &"{Gray}═══════════════════════════════════════════{Reset}"
  echo ""
  echo "SUMMARY"
  echo &"  Attempts:   {stats.attempts}"
  echo &"  {Green}Successes:{Reset}  {stats.successes}"
  echo &"  Failures:   {stats.failures}"
  echo &"  Errors:     {stats.errors}"
  echo &"  Duration:   {formatDuration(elapsed)}"
  echo &"  Rate:       {stats.attempts.float / elapsed:.1f} attempts/sec"

proc generateCredentials(users: seq[string], passwords: seq[string]): seq[Credential] =
  result = @[]
  for user in users:
    for pass in passwords:
      result.add(Credential(username: user, password: pass))

proc runBrute(config: Config) {.async.} =
  var stats = Stats(startTime: epochTime())
  
  if not config.jsonOutput:
    printBanner()
    echo &"Target: {Cyan}{config.host}:{config.port}{Reset}"
    echo &"Concurrency: {config.concurrency} | Timeout: {config.timeout}s"
    echo ""
  
  # Check if SSH is alive
  if not config.jsonOutput:
    stdout.write("Checking SSH service... ")
    stdout.flushFile()
  
  let alive = await checkSSH(config.host, config.port, config.timeout)
  if not alive:
    echo &"{Red}FAILED{Reset} - SSH service not responding"
    return
  
  if not config.jsonOutput:
    echo &"{Green}OK{Reset}"
    echo ""
  
  # Generate credential list
  let credentials = generateCredentials(config.userlist, config.passlist)
  
  if not config.jsonOutput:
    echo &"Testing {credentials.len} credential combinations..."
    echo ""
  
  # Process credentials with concurrency limit
  var pending: seq[Future[AttemptResult]] = @[]
  var foundCreds: seq[Credential] = @[]
  
  for cred in credentials:
    # Add delay if configured
    if config.delay > 0:
      await sleepAsync(config.delay)
    
    # Wait if at concurrency limit
    while pending.len >= config.concurrency:
      let idx = await pending.any()
      let res = await pending[idx]
      pending.delete(idx)
      
      stats.attempts += 1
      if res.success:
        stats.successes += 1
        foundCreds.add(res.credential)
      elif res.error.len > 0 and res.error != "Auth failed":
        stats.errors += 1
      else:
        stats.failures += 1
      
      if config.jsonOutput:
        printJsonResult(res)
      else:
        printResult(res, config.verbose)
    
    # Start new attempt
    pending.add(tryCredential(config.host, config.port, cred, config.timeout))
  
  # Wait for remaining
  for fut in pending:
    let res = await fut
    stats.attempts += 1
    if res.success:
      stats.successes += 1
      foundCreds.add(res.credential)
    elif res.error.len > 0 and res.error != "Auth failed":
      stats.errors += 1
    else:
      stats.failures += 1
    
    if config.jsonOutput:
      printJsonResult(res)
    else:
      printResult(res, config.verbose)
  
  let elapsed = epochTime() - stats.startTime
  
  if not config.jsonOutput:
    printStats(stats, elapsed)
    
    if foundCreds.len > 0:
      echo ""
      echo &"{Green}Valid credentials found:{Reset}"
      for cred in foundCreds:
        echo &"  {cred.username}:{cred.password}"

proc main() =
  var config = Config(
    host: "",
    port: 22,
    userlist: DefaultUsers,
    passlist: DefaultPasswords,
    timeout: 5,
    concurrency: 10,
    verbose: false,
    jsonOutput: false,
    delay: 0
  )
  
  var p = initOptParser()
  
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "t", "target":
        config.host = p.val
      of "p", "port":
        config.port = parseInt(p.val)
      of "U", "userlist":
        config.userlist = loadWordlist(p.val)
      of "P", "passlist":
        config.passlist = loadWordlist(p.val)
      of "u", "user":
        config.userlist = @[p.val]
      of "w", "pass":
        config.passlist = @[p.val]
      of "c", "concurrency":
        config.concurrency = parseInt(p.val)
      of "T", "timeout":
        config.timeout = parseInt(p.val)
      of "d", "delay":
        config.delay = parseInt(p.val)
      of "v", "verbose":
        config.verbose = true
      of "j", "json":
        config.jsonOutput = true
      of "h", "help":
        printHelp()
        quit(0)
      else:
        echo &"Unknown option: {p.key}"
        quit(1)
    of cmdArgument:
      if config.host == "":
        config.host = p.key
  
  if config.host == "":
    printHelp()
    quit(1)
  
  waitFor runBrute(config)

when isMainModule:
  main()
