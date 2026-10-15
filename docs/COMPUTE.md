# Borrowing another machine's compute

## What is and is not possible

Three different things get called "using another computer's resources", and
they are not the same. Being clear about which is which saves a lot of
disappointment.

**Running work elsewhere — yes.** Send your code and data to a machine with
more cores or a bigger GPU, run it there, get the output and the files back.
This is `locnet job`, and it is what most people actually want.

**Splitting work across machines — yes, with your language's help.** Julia's
`Distributed`, MPI, Dask, Ray and Spark all farm tasks out to worker processes
on other hosts. LocNet does not replace them; it supplies the thing they need
and an ordinary office network does not have — stable addresses that survive
NAT, and machines that can reach each other at all. See `locnet julia`.

**Pooling RAM or cores into one bigger computer — no.** You cannot run a
single-threaded program and have it use another machine's cores, and you cannot
allocate a 200 GB array on a machine with 32 GB by borrowing a neighbour's
memory. Nothing at this layer can do that. Single-system-image clusters
(ScaleMP, Kerrighed) tried and are effectively dead, because the moment a
program touches memory that lives on another machine it stalls for a network
round trip — roughly 10,000× slower than local RAM. Software that "uses
multiple machines" always turns out to be message passing with the messages
made tidy. LocNet takes the same honest route.

So: divide the work, or move the work. Do not expect the machines to merge.

---

## Which machine, and why

```bash
locnet best
locnet best -gpu -vram 8
```

```
RANK  MACHINE              SCORE  WHY
1     linuxbox (this one)  234    18 of 20 cores free, 25.3 GB RAM free
2     hubpc                84     6 of 8 cores free, 12.1 GB RAM free
```

Ranking is on **free** capacity, not on hardware size. A 64-core server at 95%
load has about three usable cores and will finish your job after an idle
eight-core laptop does.

Requirements are exclusions, not penalties. A job that needs 20 GB of VRAM sent
to an 8 GB card does not run slowly — it fails. So machines that cannot meet
the requirement are removed, and the refusal names each one and what it lacked:

```
no machine meets what this job needs:
  linuxbox       largest card has 3.7 GB free, needs 20.0 GB
  hubpc          no GPU detected
```

GPUs are found with the vendor's own tool (`nvidia-smi`, `rocm-smi`), because
that is the only thing that reports *free* card memory, which is the number
that decides whether a model loads. Free VRAM is the largest single card, never
the sum: two 8 GB cards do not hold a 12 GB model.

---

## Running a job elsewhere

```bash
locnet job -- julia -t 16 simulate.jl
locnet job -gpu -vram 8 -- python train.py
locnet job -on lab-1 -dir ./sim -- make -j32
```

What happens: the folder is staged to `~/.locnet/jobs/<name>-<time>` on the far
machine (rsync when available, so a re-run after editing one file sends one
file), the command runs there with output streaming back live, the folder is
copied back so files the job wrote appear locally, and the scratch directory is
removed.

A pty is forced for the remote command, because Julia, Python and most other
runtimes switch to block buffering when they think they are writing to a file —
without it a ten-minute job prints nothing and then everything.

Results come back **even when the job failed**. A crashed run's partial output
is usually the reason you wanted to look.

**On a Windows machine** the command runs in PowerShell (`powershell
-EncodedCommand`, whatever shell the far sshd hands out), so write it as you
would at a PowerShell prompt: `locnet job -on winpc-01 -- python train.py` or
`'Get-ChildItem; python run.py'`. The folder goes over with `scp` (there is no
rsync on Windows), lands in `%USERPROFILE%\.locnet\jobs\…`, and `-env K=V`
sets `$env:K`. No pty is used there — Windows' console layer swallows a pty's
output and exit status — so a program that buffers when piped may print in
bursts. A failing command is reported as failed; when the far sshd's shell is
PowerShell its exit code arrives as 1 rather than the exact number.

| Flag | |
|---|---|
| `-on <peer>` | pick the machine yourself |
| `-dir <path>` | folder to send (default `.`) |
| `-back=false` | do not copy back |
| `-keep` | leave the remote copy for inspection |
| `-exclude a,b` | patterns not to send |
| `-env K=V` | environment for the command |
| `-gpu -vram N -cpus N -mem N` | requirements |

Ctrl-C stops the job here and on the far machine — each transfer runs in its own
process group, so killing it takes the `ssh` that `scp` forks with it.

---

## Julia

```bash
locnet julia
locnet julia -procs 8 -on lab-1,lab-2
locnet julia -machine-file hosts.txt
```

prints a ready `addprocs` call:

```julia
using Distributed
addprocs([
    ("username@10.99.0.1", 8),   # hubpc — 6 of 8 cores free, 12.1 GB RAM free
];
    exename  = "julia",
    tunnel   = false,        # LocNet already carries the traffic
    sshflags = `-o BatchMode=yes -o StrictHostKeyChecking=accept-new`,
    topology = :master_worker,
)
```

`tunnel = false` matters: Julia's default tunnels worker traffic through SSH
because it assumes the hosts cannot reach each other directly. On LocNet they
can, and the tunnel only adds latency to every message.

Two shapes, and they compose:

- **`Threads` inside one machine** — shared memory, no copying. Use the biggest
  single machine: `locnet job -- julia -t auto run.jl`.
- **`Distributed` across machines** — separate processes, data moves by
  message. Use `locnet julia`. Worth it when tasks are chunky; a `pmap` over a
  million cheap items spends all its time on messages.

Each machine needs the same Julia version and the packages your script uses.
`locnet exec 'julia -e "using Pkg; Pkg.instantiate()"' -on all` after copying a
`Project.toml` is the usual way.

---

## A worked example: batch inference across the fleet

The case this is actually good at: a pile of independent GPU jobs, a handful of
machines with different cards, and nobody wanting to think about which job goes
where.

**1. Find out who can hold the model.** Requirements are exclusions, so ask
before you queue anything:

```bash
locnet best -gpu -vram 3
```

```
RANK  MACHINE              SCORE  WHY
1     linuxbox (this one)  294    19 of 20 cores free, 17.2 GB RAM free, NVIDIA GeForce RTX 3050 Laptop GPU (3.7 GB free)
—     macbook                     skipped: offline
—     hubpc                       skipped: no GPU detected
```

Ask for more than the fleet has and it says so, per machine, rather than
queueing work that will fail:

```
RANK  MACHINE         SCORE  WHY
—     (none qualify)         
—     linuxbox               skipped: largest card has 3.7 GB free, needs 24.0 GB
—     macbook                skipped: offline
—     hubpc                  skipped: no GPU detected
```

Free VRAM is the largest *single* card, never the sum: two 8 GB cards do not
hold a 12 GB model. It comes from the vendor's own tool (`nvidia-smi`,
`rocm-smi`), because that is the only thing that reports free card memory,
which is the number that decides whether a model loads.

**2. Queue the sweep.** One submission, many jobs; the hub holds them and the
machines that qualify take them as they free up:

```bash
locnet queue submit -n 240 -gpu -vram 3 -label nightly-embed -- \
    python3 /srv/embed.py --shard $LOCNET_JOB_INDEX --of 240
```

Nothing is pushed. Workers ask for work, so a laptop that is asleep, busy, or
carried out of the building mid-job needs no special handling — its lease
lapses and the shard goes to somebody else.

**3. Watch it drain.**

```bash
locnet queue
locnet queue show <id>
```

```
j0eb53044cd  done  /bin/sh -c nvidia-smi --query-gpu=name,memory.free --format=csv,noheader
  ran on linuxbox in 0.1s
--- output
NVIDIA GeForce RTX 3050 Laptop GPU, 3746 MiB
```

The GPU is visible inside the job exactly as it is to a local process — no
container, no device plumbing, because the job runs as a normal process under
the account that machine chose.

**Consent runs the other way to a normal scheduler.** The hub decides *which*
machine, but a machine only takes queued work if its own access list already
names the submitter:

```bash
locnet compute enable -allow research-team -user builder
```

Nothing the hub says can make a machine run your job. That is the property that
makes it reasonable to point this at other people's workstations.

### Where this would strain in an organization

Worth knowing before anyone depends on it:

- **Output arrives at the end, not as it runs.** A six-hour fine-tune gives you
  nothing to watch. Long jobs want streamed logs; this returns stdout when the
  job exits.
- **Nothing returns artifacts.** `locnet job` moves a folder there and back;
  the *queue* returns only output, so a job that writes checkpoints has to put
  them somewhere itself — a share, or object storage.
- **One job at a time is not enforced.** Two GPU jobs can land on one card and
  both run out of memory. Requirements are checked when the job is scheduled,
  against stats up to 30 seconds old, and nothing reserves the card in between.
- **No priority between people**, only the per-job `-priority` number, so one
  person's 500-job sweep occupies the fleet ahead of somebody's single urgent
  job.
- **The hub is a single point of failure for scheduling.** A standby mirrors it
  and takes over on one command, but a human gives that command.

Running work already in flight survives all of these; they are about the fleet
being *shared* rather than about it working.

---

## Local language models

`locnet best -gpu -vram 24` finds the machine that can hold the model. Then
either run the server there and point clients at its overlay address:

```bash
locnet exec 'ollama serve' -on gpu-box       # or: systemctl --user start ollama
export OLLAMA_HOST=http://10.99.0.3:11434    # from any machine on the mesh
```

or send the job to it with `locnet job -gpu -- python infer.py`.

Splitting one model across several machines' GPUs is possible with llama.cpp's
RPC backend, but it is slower than a single card that fits the model unless the
model genuinely does not fit anywhere. Check `locnet best -gpu` first.

---

## Two compute paths, deliberately

| | `locnet job` / `locnet exec` | `locnet run` |
|---|---|---|
| Transport | SSH | LocNet's own channel |
| Needs an account there | yes | no |
| Needs the far machine to opt in | no | yes (`locnet compute`) |
| Shell | full | none — argv is exec'd as given |
| Good for | machines you own | lending cycles to colleagues |

There is a third: [the queue](QUEUE.md), for work that should run on *whichever*
machine is free rather than on one you picked. `locnet job` moves a folder to a
machine now; `locnet queue` leaves work on the hub until a machine that meets
its requirements asks for something to do.

The second exists because "let a coworker use my spare cores" and "administer
my own fleet" are different problems. Giving out an SSH account for the first
is far more access than the task needs.

---

## Setup, once per machine

```bash
locnet login <peer> <account>    # which account you have over there
locnet ssh-key <peer>            # copy your key; asks for that machine's password once
```

Or, with no passwords at all, exchange keys over the mesh once:
`locnet ssh-keys publish` on your machine and `locnet ssh-keys accept <your
machine>` on the other (see `locnet ssh-keys -h`).

Everything here runs with `BatchMode=yes` and never prompts. A fan-out that
stops on machine three waiting for a password nobody can see is worse than one
that fails, so a missing key fails immediately with:

```
SSH refused the login. Set up a key:  locnet ssh-key <peer>
```

---

## VS Code

`editors/vscode` is an extension that runs the current file on the best machine
and streams output into the editor — `Ctrl+Alt+R`. It shells out to `locnet job`
rather than reimplementing any of this, so it cannot drift from the CLI. See
its README for settings.
