# upl — Policy Engine

`upl.dll` is a security-policy engine for Windows CE and Windows Phone 7. It
comes from the FullUnlock v4.0 project (© Maxim Menshikov (ultrashot), 2012). It stands in for the
stock policy engine that the OS consults to authorize access to protected
resources. It relaxes those decisions, so the engine grants unsigned and
third-party code the access it would normally deny.

The project builds from the folder that was named `newpl`. The project and the
module are both called `upl` (`upl.dll`).

This is legacy research and homebrew code for a platform that reached end of
life long ago.

## How it works

The engine exports the `PolicyRule*`, `PolicyEngineInit`, and `GetFunctionTable`
entry points (see `upl.def`). The OS policy client calls them. Each authorization
request arrives as an IRI (a canonical resource name). The decision path is:

1. `BuildIri.cpp` reconstructs the canonical IRI for the request.
2. `Branches.cpp` classifies the IRI. For example, it asks whether the request is
   an unsigned native DLL load.
3. `SecurityCheck.cpp` makes the decision. For a branch that the OS would
   normally refuse, it checks whether the caller's account is privileged
   (`AccountManager` and `adb7`). If so, it allows the request. If not, it denies
   the request and posts an `ACCESS_DENIED` record to a message queue
   (`PolicyMsgQueue.cpp`). The companion UI (`uplhlp`) reads that queue.

The engine links the IRI helper library (`iri.lib`) and the loader-verifier
import library (`ulv.lib`).

## Layout

```
upl/
├── upl.vcproj          Visual Studio 2008 project (WM6 Pro / WP7 ARMv4I)
├── .clang-format       Formatting rules for src/
├── src/                Project sources
│   ├── upl.cpp             Policy* exports and function table
│   ├── PolicyEngine.cpp/.h     Engine entry points
│   ├── SecurityCheck.cpp/.h    Authorization decision
│   ├── Branches.cpp/.h         IRI branch classification
│   ├── BuildIri.cpp/.h         Canonical IRI reconstruction
│   ├── PolicyMsgQueue.cpp/.h   ACCESS_DENIED message queue
│   ├── PrivilegeCheck.h        Privilege predicates
│   ├── AccountManager.cpp/.h, adb7.cpp   ADB account helpers
│   ├── Protection.cpp      Anti-tamper stub
│   ├── stdafx.h/.cpp        Precompiled-header stub
│   ├── debug.h, resource.h, resources.rc
│   └── upl.def             Exported Policy* entry points
└── sdk/                Vendored SDK headers + import libraries
    ├── iri.h + iri.lib     IRI (canonical resource name) API
    ├── adb7.h              ADB (account database) API
    ├── ulv.lib             Loader-verifier import library
    └── coredll7.lib
```

## Building

You need Visual Studio 2008 with the Windows Mobile 6 Professional SDK (ARMV4I),
the WP7SDK (ARMv4I), or both installed. To build the engine:

1. Open `upl.vcproj`.
2. Build a Release configuration.

The output is `upl.dll`. The include and library paths point at `src/` and
`sdk/`. The project is self-contained and does not need an enclosing solution.
`iri.lib`, `ulv.lib`, and `coredll7.lib` are vendored under `sdk/`.
