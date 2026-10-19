/** The example's page script, bundled to public/app.js (see build.mjs). */

import { authErrorMessage, createAuthClient, passkeysSupported, type Account } from "../../src/client/index";

const auth = createAuthClient();
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function show(id: "signed-out" | "signed-in") {
  $("signed-out").hidden = id !== "signed-out";
  $("signed-in").hidden = id !== "signed-in";
}

function say(message: string | null) {
  $("message").textContent = message ?? "";
}

/** Run a button's action, showing what went wrong in plain words. */
function action(id: string, run: () => Promise<unknown>, fallback = "Something went wrong") {
  $(id).addEventListener("click", async () => {
    say(null);
    try {
      await run();
    } catch (e) {
      say(authErrorMessage(e, fallback));
    }
  });
}

async function render(account: Account | null | undefined) {
  if (!account) return show("signed-out");
  show("signed-in");
  $("who").textContent = account.name;
  $("email").textContent = account.email ?? "none";
  $("hello").textContent = ((await (await fetch("/api/hello")).json()) as { message: string }).message;
  const keys = await auth.passkeys();
  const list = $("passkeys");
  list.replaceChildren(
    ...keys.map((k) => {
      const li = document.createElement("li");
      li.textContent = `Added ${new Date(k.createdAt).toLocaleString()} `;
      const remove = document.createElement("button") as HTMLButtonElement;
      remove.textContent = "Remove";
      remove.onclick = async () => {
        say(null);
        try {
          await auth.removePasskey(k.id);
          await render(await auth.session());
        } catch (e) {
          say(authErrorMessage(e, "Couldn't remove it"));
        }
      };
      li.appendChild(remove);
      return li;
    }),
  );
}

action("register", async () => render(await auth.register($<HTMLInputElement>("name").value)));
action("sign-in", async () => render(await auth.signIn()));
action("recover-start", async () => {
  await auth.startRecovery($<HTMLInputElement>("recover-email").value);
  say("If that email has an account, a code is on its way.");
});
action("recover-finish", async () => {
  const account = await auth.finishRecovery($<HTMLInputElement>("recover-email").value, $<HTMLInputElement>("recover-code").value);
  // Every passkey was revoked: give this device one.
  await auth.addPasskey();
  await render(account);
});
action("email-start", async () => {
  await auth.startEmailVerification($<HTMLInputElement>("new-email").value);
  say("Check your email for a code.");
});
action("email-finish", async () =>
  render(await auth.finishEmailVerification($<HTMLInputElement>("new-email").value, $<HTMLInputElement>("email-code").value)),
);
action("add-passkey", async () => {
  await auth.addPasskey();
  await render(await auth.session());
});
action("sign-out-others", async () => {
  await auth.signOutOtherDevices();
  say("Other devices are signed out.");
});
action("sign-out", async () => {
  await auth.signOut();
  show("signed-out");
});
action("delete", async () => {
  await auth.deleteAccount();
  show("signed-out");
  say("Account deleted.");
});

if (!passkeysSupported()) say("This browser can't use passkeys.");
render(await auth.session());
