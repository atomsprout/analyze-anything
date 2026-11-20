# The deep level: which code does what

Off unless you ask for it with `--deep`.

The analysis reads the structure of files. It can tell you that a program imports `dlopen`, or that an address is written somewhere in it. It cannot tell you **which function** calls `dlopen` or uses that address: that takes disassembling the code and following its references, which is what disassemblers are for. With `--deep`, Analyze Anything hands the program files of the input to a disassembler you have installed and asks it.

```
analyze-anything deep ghidra --path ~/tools/ghidra_12.1.4_PUBLIC   # once: say which tool, and where it is
analyze-anything App.ipa --deep                                    # analyze, and ask the tool as well
```

## The tools

| | How it is run | Notes |
|---|---|---|
| **Ghidra** | `support/analyzeHeadless`, with no window | Free. Needs a Java runtime, as Ghidra itself does. Found through `--path`, `GHIDRA_INSTALL_DIR`, or `analyzeHeadless` on the search path |
| **Hopper** | the `hopper` launcher inside the app | Opens each file as a document in the Hopper app on your screen and closes it when done. Much faster than Ghidra. Found in the Applications folder, or through `--path` |

```
analyze-anything deep                       # which tool would be asked, and where it is
analyze-anything deep hopper                # choose Hopper
analyze-anything App.ipa --deep --deep-tool ghidra   # another tool for this one run
```

With nothing chosen, Ghidra is used when it is found, else Hopper. The choice is kept in `~/.analyze-anything/deep.toml`:

```toml
tool = "ghidra"
ghidra = "/Users/me/tools/ghidra_12.1.4_PUBLIC"
max_files = 4      # most program files of one input handed to the tool; the largest come first
seconds = 900      # longest the tool may spend on one of them
```

## What it adds to the report

In the chapter **Code insight**, for each program file that was handed over:

- **Read in depth by a disassembler**: which tool and version, for which processor, and how many functions it made out.
- **Code that …**: the functions that use APIs of seven kinds: opening network connections, starting other programs, loading code at run time, encrypting or hashing, looking for or using a debugger, reaching into other processes, and reading or writing secrets the system keeps. Each names the functions and their addresses.
- **Code that uses an address**: for the addresses (URLs) the content analysis found in that file, the functions that refer to them.

For example, from a real app:

> The address `https://twitter.com/tblodt` is referred to by 1 function: `-[AboutViewController tableView:didSelectRowAtIndexPath:]` (0x10002154c). From Hopper 6.6.2.

The evidence of each finding is the place in the file where the call or the reference is, with the function it is in, so the desktop app's byte view and your own disassembler can go straight to it.

A universal Mach-O holds one program per processor; one of them is read, the arm64 one when there is one.

## How it keeps to the rules

- **Nothing of the input is run.** The tool is given a copy of the file to read, in a folder of its own that is removed afterwards.
- **Kept apart.** Every finding from this level names the tool and its version, is marked `derived`, and is a neutral fact: it does not change the counts of what needs attention.
- **Repeatable with the same tool.** The same input and the same version of the tool give the same report. Another version, or the other tool, may read the code differently: they name functions without symbols in their own way (`FUN_100016344`, `sub_100016344`) and may make out a different number of functions.
- **Said when it does not happen.** A file the tool could not finish, and the program files that were not handed over because of the limits, are listed under coverage and limitations.
- **Off means off.** Without `--deep` no other program is started and the report is what it always was.

## What has been tried

| | |
|---|---|
| Ghidra 12.1.4 | Run on a real IPA (iSH 1.3.2: an arm64 Mach-O and three 32-bit x86 ELF files) and on `/bin/ls`: 20 findings, about seven and a half minutes for the four files |
| Hopper 6.6.2 | The same IPA (two files) in 18 seconds, and a Linux x86-64 program. For the app's main program it names the same functions at the same addresses as Ghidra, for every kind of API and every address |

Not tried: Windows programs (PE) with either tool, Ghidra on Linux or Windows, universal binaries with Hopper's own FAT loader (the part is taken out before either tool sees it).

## Limits

- The list of APIs is fixed and short. A program that reaches the same thing another way (a system call made directly, a library of its own) is not seen.
- Calls through a pointer or through Objective-C or Swift message sends are found only as far as the tool resolves them.
- Hopper is an app with windows: its documents appear on screen while it works. A run that is given up on after its time cannot stop Hopper's own analysis; the document stays open in Hopper.
- IDA is not supported. The two tools are behind one interface, so it is one more implementation of it, to be written where it can be tried.
- The desktop app does not offer this level yet.
