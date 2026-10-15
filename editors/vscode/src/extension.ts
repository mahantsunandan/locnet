// LocNet Compute — run the file you are editing on a more powerful machine.
//
// The extension is deliberately thin. It shells out to the `locnet` CLI rather
// than reimplementing placement, staging or transfer in TypeScript: the CLI is
// what gets tested, and an editor plugin that quietly diverges from the tool it
// wraps is worse than no plugin. Everything here is argument building, a status
// bar, and streaming output into a panel.

import * as vscode from "vscode";
import { spawn, execFile } from "child_process";
import * as path from "path";

let output: vscode.OutputChannel;
let statusItem: vscode.StatusBarItem;
let running: ReturnType<typeof spawn> | undefined;

interface Machine {
  name: string;
  host: string;
  self: boolean;
  usable: boolean;
  score: number;
  reason?: string;
  skipped?: string;
  cpus?: number;
  mem_free_mb?: number;
  gpu?: string;
  gpu_free_mb?: number;
}

function cfg<T>(key: string, fallback: T): T {
  return vscode.workspace.getConfiguration("locnet").get<T>(key) ?? fallback;
}

function locnet(): string {
  return cfg<string>("path", "locnet");
}

/** Ask the CLI which machines exist and how much of each is free. */
function machines(extraArgs: string[] = []): Promise<Machine[]> {
  return new Promise((resolve, reject) => {
    execFile(locnet(), ["best", "-json", ...extraArgs], { timeout: 15000 },
      (err, stdout, stderr) => {
        if (err) {
          // The most common causes are "not installed" and "daemon not
          // running", and both are worth saying plainly rather than
          // surfacing a spawn error.
          reject(new Error(stderr?.trim() || err.message));
          return;
        }
        try {
          resolve(JSON.parse(stdout) as Machine[]);
        } catch {
          reject(new Error("could not read `locnet best -json` output"));
        }
      });
  });
}

/** The workspace folder holding the file, which is what gets staged. */
function workspaceFor(doc: vscode.TextDocument): vscode.WorkspaceFolder | undefined {
  return vscode.workspace.getWorkspaceFolder(doc.uri);
}

/**
 * Build the remote command for a document.
 *
 * The path handed to the far machine is *relative* to the workspace root,
 * because that is the directory that gets staged. Sending an absolute local
 * path would name a directory that does not exist over there — the classic way
 * this kind of integration fails, and it fails at run time rather than here.
 */
function remoteCommand(doc: vscode.TextDocument, root: string): string | undefined {
  const templates = cfg<Record<string, string>>("commands", {});
  const tpl = templates[doc.languageId];
  if (!tpl) { return undefined; }

  const rel = path.relative(root, doc.uri.fsPath).split(path.sep).join("/");
  const threads = cfg<string>("juliaThreads", "auto");
  return tpl.replace(/\$\{file\}/g, quote(rel)).replace(/\$\{threads\}/g, threads);
}

function quote(s: string): string {
  return /[^A-Za-z0-9._\/-]/.test(s) ? `'${s.replace(/'/g, `'\\''`)}'` : s;
}

/** Run one job, streaming its output into the panel. */
async function runJob(args: string[], label: string) {
  if (running) {
    vscode.window.showWarningMessage("A LocNet job is already running. Stop it first.");
    return;
  }

  output.show(true);
  output.appendLine("");
  output.appendLine(`──── ${new Date().toLocaleTimeString()}  ${label}`);
  output.appendLine(`$ ${locnet()} ${args.join(" ")}`);

  statusItem.text = "$(sync~spin) LocNet: running";

  const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const proc = spawn(locnet(), args, { cwd });
  running = proc;

  proc.stdout?.on("data", (d: Buffer) => output.append(d.toString()));
  proc.stderr?.on("data", (d: Buffer) => output.append(d.toString()));

  proc.on("error", (e) => {
    output.appendLine(`\ncould not start ${locnet()}: ${e.message}`);
    vscode.window.showErrorMessage(
      `LocNet: could not run "${locnet()}". Set locnet.path if it is installed elsewhere.`);
  });

  proc.on("close", (code) => {
    running = undefined;
    refreshStatus();
    if (code === 0) {
      output.appendLine("\n✓ finished");
    } else {
      output.appendLine(`\n✗ exited ${code}`);
      vscode.window.showErrorMessage(`LocNet job failed (exit ${code}). See the LocNet output panel.`);
    }
  });
}

/** Shared entry point for the three run commands. */
async function run(opts: { machine?: string; gpu?: boolean }) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Open a file to run.");
    return;
  }
  const doc = editor.document;
  if (doc.isUntitled) {
    vscode.window.showWarningMessage("Save the file first — LocNet sends the folder it lives in.");
    return;
  }
  await doc.save();

  const folder = workspaceFor(doc);
  if (!folder) {
    vscode.window.showWarningMessage(
      "Open the containing folder as a workspace. LocNet stages the folder, not the single file.");
    return;
  }
  const root = folder.uri.fsPath;

  const command = remoteCommand(doc, root);
  if (!command) {
    vscode.window.showWarningMessage(
      `No run command configured for "${doc.languageId}". Add one under locnet.commands.`);
    return;
  }

  const args = ["job", "-dir", root, "-exclude", cfg<string>("exclude", "")];
  if (!cfg<boolean>("syncBack", true)) { args.push("-back=false"); }

  const machine = opts.machine ?? cfg<string>("machine", "");
  if (machine) { args.push("-on", machine); }
  if (opts.gpu) { args.push("-gpu"); }
  args.push("--", command);

  await runJob(args, `${path.basename(doc.uri.fsPath)} → ${machine || (opts.gpu ? "best GPU machine" : "best machine")}`);
}

/** A quick-pick of machines, showing what each has free. */
async function pick(gpuOnly = false): Promise<string | undefined> {
  let list: Machine[];
  try {
    list = await machines(gpuOnly ? ["-gpu"] : []);
  } catch (e: any) {
    vscode.window.showErrorMessage(`LocNet: ${e.message}`);
    return undefined;
  }

  const items: vscode.QuickPickItem[] = list.map((m) => ({
    label: m.self ? `${m.name}  (this computer)` : m.name,
    description: m.usable ? `score ${Math.round(m.score)}` : "unavailable",
    // The reason is the useful part: it is what lets someone tell whether
    // the ranking agrees with what they know about their own machines.
    detail: m.usable ? m.reason : `skipped — ${m.skipped}`,
  }));
  if (items.length === 0) {
    vscode.window.showWarningMessage("LocNet: no machines on this network yet.");
    return undefined;
  }

  const chosen = await vscode.window.showQuickPick(items, {
    title: "Run on which machine?",
    matchOnDetail: true,
  });
  return chosen ? chosen.label.split("  ")[0] : undefined;
}

async function refreshStatus() {
  if (running) { return; }
  try {
    const list = await machines();
    const pinned = cfg<string>("machine", "");
    const best = list.find((m) => m.usable && !m.self) ?? list.find((m) => m.usable);
    const name = pinned || best?.name;
    statusItem.text = name ? `$(server) LocNet: ${name}` : "$(server) LocNet: no machines";
    statusItem.tooltip = new vscode.MarkdownString(
      list.map((m) => m.usable
        ? `**${m.name}** — ${m.reason}`
        : `~~${m.name}~~ — ${m.skipped}`).join("\n\n") || "No machines found.");
  } catch {
    statusItem.text = "$(server) LocNet: offline";
    statusItem.tooltip = "locnetd is not reachable. Is the service running?";
  }
  statusItem.show();
}

export function activate(context: vscode.ExtensionContext) {
  output = vscode.window.createOutputChannel("LocNet");
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusItem.command = "locnet.pickMachine";
  context.subscriptions.push(output, statusItem);

  context.subscriptions.push(
    vscode.commands.registerCommand("locnet.runHere", () => run({})),
    vscode.commands.registerCommand("locnet.runGPU", () => run({ gpu: true })),

    vscode.commands.registerCommand("locnet.runOn", async () => {
      const m = await pick();
      if (m) { await run({ machine: m }); }
    }),

    vscode.commands.registerCommand("locnet.pickMachine", async () => {
      const m = await pick();
      if (m === undefined) { return; }
      await vscode.workspace.getConfiguration("locnet")
        .update("machine", m, vscode.ConfigurationTarget.Workspace);
      refreshStatus();
    }),

    vscode.commands.registerCommand("locnet.showMachines", async () => {
      output.show(true);
      try {
        const list = await machines();
        output.appendLine("");
        output.appendLine("Machine          Free capacity");
        for (const m of list) {
          const tag = m.self ? " (this one)" : "";
          output.appendLine(m.usable
            ? `  ${(m.name + tag).padEnd(22)} ${m.reason}`
            : `  ${(m.name + tag).padEnd(22)} skipped — ${m.skipped}`);
        }
      } catch (e: any) {
        output.appendLine(`error: ${e.message}`);
      }
    }),

    vscode.commands.registerCommand("locnet.juliaSnippet", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) { return; }
      execFile(locnet(), ["julia"], { timeout: 15000 }, (err, stdout, stderr) => {
        if (err) {
          vscode.window.showErrorMessage(`LocNet: ${stderr?.trim() || err.message}`);
          return;
        }
        // Drop the trailing "requirements" comment block; it belongs in the
        // output panel, not pasted into someone's script.
        const code = stdout.split("\n# Requirements on each machine")[0];
        editor.edit((b) => b.insert(editor.selection.active, code));
      });
    }),

    vscode.commands.registerCommand("locnet.cancel", () => {
      if (!running) {
        vscode.window.showInformationMessage("No LocNet job is running.");
        return;
      }
      // SIGINT rather than SIGKILL: the CLI installs a handler that stops the
      // remote side too, and killing it outright would leave the far machine
      // still working.
      running.kill("SIGINT");
      output.appendLine("\nstopping…");
    }),
  );

  refreshStatus();
  const timer = setInterval(refreshStatus, 20000);
  context.subscriptions.push({ dispose: () => clearInterval(timer) });
}

export function deactivate() {
  running?.kill("SIGINT");
}
