# SolarWinds_Countermeasures
Description
===========
This tool is designed to identify processes, services, and drivers that SUNBURST attempts to identify on the victim's machine.  
This tool leverages the same logic SUNBURST uses to obtain a list of running processes/services/drivers, then applies the same 
hashing algorithm, and performs the blacklist check.  The outcome/results of the blacklist check are then printed to the console.


Example - when running on a system monitored by defender and sentinelone
========================================================================
```
C:\Users\infected\Desktop>sentinelone_sunburst_blacklist_checker.exe
SentinelLabs SUNBUST Blacklist Checker Version 1
Description: This tool checks the current system for processes, services, and drivers
that SUNBURST attempts to identify in its blacklist, prints the match, as well as the outcome.

[+] Checking running processes/services...
SERVICES BLACKLIST MATCH: Running process MsMpEng matches hardcoded blacklist hash 5183687599225757871
OUTCOME: SUNBURST will attempt to disable via the services registry key!

[+] Done checking running processes/services!
[+] Checking loaded drivers...
DRIVERS BLACKLIST MATCH: Loaded driver SentinelMonitor.sys matches hardcoded blacklist hash 12343334044036541897
OUTCOME: SUNBURST will exit!
[+] Done checking loaded drivers!
```

Example - when running on a malware analyst machine
===================================================
```
C:\Users\REM\Desktop>sentinelone_sunburst_blacklist_checker.exe
SentinelLabs SUNBUST Blacklist Checker Version 1
Description: This tool checks the current system for processes, services, and drivers
that SUNBURST attempts to identify in its blacklist, prints the match, as well as the outcome.

[+] Checking running processes/services...
BLACKLIST MATCH: Running process dnSpy matches hardcoded blacklist hash 13825071784440082496
OUTCOME: SUNBURST will exit!

BLACKLIST MATCH: Running process pestudio matches hardcoded blacklist hash 10235971842993272939
OUTCOME: SUNBURST will exit!

[+] Done checking running processes/services!
[+] Checking loaded drivers...
[+] Done checking loaded drivers!
```
