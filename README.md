# RelTC
A graphical user interface for generating Linux Traffic Control (`tc`) commands, using clsact. <br />
*NOTE* almost 100% of the code / ideas were generated by `windsurf`. <br />
The package-name "tcgen" was already taken...

Got hard feelings when your server is at downtime? <br />
Have another server to fill the empty place? <br />
Use TC (traffic control) utility to automatically forward packets when your server is under maintainance! <br />
The `tc` commandline is too hard to get? The `reltc` utility comes to the rescue!

## Features
- Filter packets by protocol (TCP/UDP)
- Filter by source/destination IP addresses
- Filter by source/destination ports
- Patch packet fields (/ drop packet) when filters match
- Generate ready-to-use `tc` commands

## Installation
```bash
pip install --upgrade reltc
```

## Usage
After installation, run the application with the command-line:

```bash
reltc
```
