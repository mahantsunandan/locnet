# LocNet Compute for VS Code

Run the file you are editing on a more powerful machine on your LocNet mesh.
Output streams back into the editor; files the job writes appear in your folder.

## Commands

| Command | What it does |
|---|---|
| **LocNet: Run This File on the Best Machine** (`Ctrl+Alt+R`) | Picks whichever machine has the most free CPU/RAM, sends the folder, runs, syncs back |
| **LocNet: Run This File On…** | Same, but you choose from a list showing what each machine has free |
| **LocNet: Run This File on a GPU Machine** | Restricts the choice to machines with an accelerator |
| **LocNet: Choose Target Machine** | Pins a machine for this workspace |
| **LocNet: Show Machines and Free Capacity** | The ranking, and why anything was skipped |
| **LocNet: Insert Julia addprocs() for This Mesh** | Pastes a ready `addprocs` call for Julia's `Distributed` |
| **LocNet: Stop the Running Job** | Stops it here *and* on the far machine |

The status bar shows the machine that would be used; hovering lists every
machine and its free capacity.

## Requirements

- `locnet` on your PATH, and the mesh up (`locnet status`)
- An account on the far machine and a key, once:
  `locnet login <peer> <account> && locnet ssh-key <peer>`
- The interpreter installed over there — this sends your code, not your runtime

## Settings

`locnet.commands` maps a language id to a command line. `${file}` is the path
relative to the workspace root; `${threads}` is `locnet.juliaThreads`.

```jsonc
"locnet.commands": {
  "julia":  "julia -t ${threads} ${file}",
  "python": "python3 ${file}"
}
```

Others: `locnet.machine` (pin a target), `locnet.syncBack`, `locnet.exclude`,
`locnet.path`.

## How it works

Everything is `locnet job` under the hood — the extension builds arguments and
streams output. It deliberately does not reimplement placement or transfer, so
it cannot drift from the tool it wraps.

## Building

```bash
npm install && npm run compile
```

Then F5 in VS Code, or `npx vsce package` for a `.vsix`.
