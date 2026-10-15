# The job queue

```bash
locnet queue submit -cpus 16 -- make -j16
locnet queue submit -gpu -vram 20 -- python train.py
locnet queue submit -n 40 -- ./render.sh          # forty frames, forty machines
locnet queue                                       # what is waiting, what is running
locnet queue log j3f9a21b4c
```

`locnet job` and `locnet run` send work to a machine you have chosen, now.
The queue is for work you want done *eventually*, on whichever machine turns
out to be free — a nightly build, a parameter sweep, forty render frames, a
test suite that takes an hour and does not care where it runs.

---

## Where the queue lives, and why

On the hub. It is the machine that is already always on and already keeps a
durable record of who exists and how loaded they are, so putting the queue
anywhere else would mean a second always-on thing to run.

Nothing is pushed. Workers ask for work, which means:

- A machine that is **asleep** is not a machine anything has to route around.
  It simply is not asking.
- A machine that is **busy** finishes what it has before asking again.
- A machine that is **switched off mid-job** stops asking. Its job's lease runs
  out and the hub gives the work to somebody else.
- A fleet where **everything is off** loses nothing. The jobs sit on the hub
  until a machine comes back.

None of those cases needed any code; they fall out of pulling rather than
pushing.

---

## Who runs what

A machine takes queued work only if its own compute setting already names the
submitter:

```bash
# on the machine that will do the work
locnet compute enable -allow workstation -user builder
```

That is the same access list that governs `locnet run`, deliberately. There is
no separate worker mode to turn on, and there is no way for the hub to
conscript a machine that has not agreed — the hub schedules, it does not
command. It is also the one part of this system that is not trusted with
execution, so a compromised hub can lose your jobs and cannot run anything
anywhere.

On Windows, `-user` names a local account and jobs run as that account
without LocNet ever holding its password (an S4U logon); an administrator's
account runs unelevated. See [SHARING.md](SHARING.md#on-windows).

`locnet queue workers` lists the machines that will take work, and is the first
thing to check when a queue is not moving.

**What other machines can see and do.** Every admitted machine sees the whole
queue — which jobs are waiting, where they run, and their commands — because
"why is nothing moving" is everybody's question. A job's environment values
and its output are shown only to the machine that submitted it, the machine
that ran it, and administrators; anyone else sees the variable names with
`…` in place of the values, and how many bytes of output there were. Only the
submitter or an administrator can cancel a job.

A machine waiting for approval (see
[OPERATIONS.md](OPERATIONS.md#device-approval)) takes no part: it cannot
submit, list, cancel, or be handed work, whatever its own compute setting
says — otherwise, by allowing `"*"` in its own setting, it could be handed
anybody's job and report any result it liked.

---

## Choosing a machine

Requirements are exclusions, not preferences. A job that needs 20 GB of VRAM
sent to an 8 GB card does not run slowly — it fails. So machines that cannot
meet the requirement are removed from consideration entirely.

| flag | |
|---|---|
| `-cpus N` | at least N cores |
| `-mem GB` | at least GB of **free** memory |
| `-disk GB` | at least GB of free disk |
| `-gpu` | any accelerator |
| `-vram GB` | GB free on a **single** card — two 8 GB cards do not hold a 12 GB model |
| `-on <peer>` | that machine and no other |
| `-priority N` | higher numbers are considered first |
| `-max <seconds>` | time limit for one attempt |

The matching happens on the hub rather than on the worker, for two reasons: the
hub already knows every machine's load from the reports it collects, and a
worker deciding for itself what it is capable of is a worker that can be made
to lie about it.

Among machines that qualify, work goes to whichever asks first. That is a
simpler rule than ranking by free capacity, and it self-balances for the same
reason a supermarket queue does: the machine that is free asks sooner.

---

## When things go wrong

**A worker disappears mid-job.** Every claim carries a lease — the job's own
time limit plus two minutes. When it expires the hub puts the job back in the
queue and somebody else picks it up. Three attempts by default; after that it
is marked failed, with a message saying which machine kept vanishing, because a
job that disappears three times will disappear a fourth.

**A worker comes back late with an answer.** Its result is refused. By then the
job may be running somewhere else, and accepting a stale result would overwrite
a live attempt.

**The hub restarts.** The queue is in its state file, so nothing is lost. Jobs
that were running are re-offered once their leases lapse.

**A job fails on its own merits** — a compile error, a missing file — and is
*not* retried. Retrying it would produce the same failure and hide it behind
two more.

**A job is cancelled while it runs.** The machine running it checks with the hub
every ten seconds and stops it — the whole process group, so a script's
children go too — and the machine is free for the next job.

**A job hits its time limit.** It is killed, children included, and reported as
failed with the reason.

---

## Output

Standard output and standard error come back to the hub and stay there:
the first and last parts of up to 256 KB of output and 64 KB of errors per job,
with a line saying how much was left out in between. `locnet queue log <id>`
prints them; an ID prefix is enough as long as it is unambiguous. Listings —
`locnet queue` and the console's Queue page — leave the output out, so a long
history costs nothing to look at.

A job that produces real output should write it to a file and put that file
somewhere the fleet can see — a files share, or a directory both machines
mount. The queue is a scheduler, not a file transfer system; `locnet job` is
the one that stages a folder and brings results back.

The last 200 finished jobs are kept and older ones are dropped.

---

## Worked example: a render farm in four lines

```bash
# once, on every machine that should help
locnet compute enable -allow workstation -user render

# from your desk
locnet queue submit -n 240 -cpus 4 -label frame -- /srv/render.sh
locnet queue                       # watch them spread out
```

Each machine picks up frames as it finishes the last one, so a fast machine
does more of them without anyone deciding that in advance. Laptops that get
closed drop out and their frames are re-queued.

`/srv/render.sh` has to work out which frame it is rendering — from a counter
file, a work directory, or an environment variable. The queue does not number
your jobs for you, because what counts as "the next unit of work" is a question
only your job can answer.

---

## What this is not

It is not Slurm, and it is not Kubernetes. There is no gang scheduling, no
reservation, no fair-share accounting between users, no dependency graph
between jobs, and no bin-packing of several jobs onto one machine — a worker
runs one job at a time. If you need those, you need one of those systems.

What it is: a way to get an organisation's idle machines to chew through a pile
of work overnight, with no new daemon to install and no scheduler to
administer, on a network you already have.
