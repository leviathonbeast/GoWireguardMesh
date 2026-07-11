import { useState } from "react";
import { api, logout } from "../api";
import type { AppCtx } from "../appctx";
import { formatTime } from "../lib/format";
import { PageHead, Section } from "../components/ui";

export default function Account({ ctx }: { ctx: AppCtx }) {
  const { account, users } = ctx.data;

  const [curPassword, setCurPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPassword2, setNewPassword2] = useState("");
  const [newUsername, setNewUsername] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [msg, setMsg] = useState("");

  const changePassword = async () => {
    setMsg("");
    if (newPassword !== newPassword2) {
      setMsg("new passwords do not match");
      return;
    }
    try {
      await api("/api/account/password", {
        method: "POST",
        body: JSON.stringify({ current_password: curPassword, new_password: newPassword }),
      });
      setCurPassword("");
      setNewPassword("");
      setNewPassword2("");
      ctx.toast("password changed");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };

  const createUser = async () => {
    setMsg("");
    try {
      await api("/api/users", {
        method: "POST",
        body: JSON.stringify({ username: newUsername.trim(), password: newUserPassword }),
      });
      setNewUsername("");
      setNewUserPassword("");
      await ctx.refresh();
      ctx.toast("user created");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };

  const deleteUser = async (id: number) => {
    setMsg("");
    try {
      await api(`/api/users/${id}/delete`, { method: "POST" });
      await ctx.refresh();
      ctx.toast("user deleted");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      <PageHead title="Account" sub="Your session, password, and the admin users of this control plane." />

      <Section title="Signed in">
        <div className="panel flex flex-wrap items-center justify-between gap-3">
          <p className="text-muted">
            {account
              ? `${account.username} · ${account.auth_source} account`
              : "No user session found."}
          </p>
          <button onClick={() => void logout()}>sign out</button>
        </div>
      </Section>

      {account && (
        <Section title="Change password">
          <div className="panel">
            <div className="form-grid">
              <label>
                <span>Current password</span>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={curPassword}
                  onChange={(e) => setCurPassword(e.target.value)}
                />
              </label>
              <label>
                <span>New password</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
              </label>
              <label>
                <span>Confirm new password</span>
                <input
                  type="password"
                  autoComplete="new-password"
                  value={newPassword2}
                  onChange={(e) => setNewPassword2(e.target.value)}
                />
              </label>
              <div>
                <button
                  className="btn-primary"
                  disabled={!curPassword || newPassword.length < 8}
                  onClick={() => void changePassword()}
                >
                  update password
                </button>
              </div>
            </div>
          </div>
        </Section>
      )}

      <Section title="Admin users">
        <div className="panel tablewrap">
          <table>
            <thead>
              <tr>
                <th>username</th>
                <th>source</th>
                <th className="hidden md:table-cell">created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 && (
                <tr>
                  <td colSpan={4} className="text-muted">
                    no users
                  </td>
                </tr>
              )}
              {users.map((u) => (
                <tr key={u.id}>
                  <td>{u.username}</td>
                  <td>{u.auth_source}</td>
                  <td className="hidden text-muted md:table-cell">{formatTime(u.created_at)}</td>
                  <td className="text-right">
                    {users.length > 1 && (!account || u.id !== account.id) && (
                      <button className="btn-danger" onClick={() => void deleteUser(u.id)}>
                        delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <h3 className="mt-4 mb-2">Add admin user</h3>
          <div className="flex max-w-xl flex-wrap gap-2">
            <input
              className="min-w-40 flex-1"
              placeholder="username"
              autoComplete="off"
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
            />
            <input
              className="min-w-40 flex-1"
              type="password"
              placeholder="password (min 8)"
              autoComplete="new-password"
              value={newUserPassword}
              onChange={(e) => setNewUserPassword(e.target.value)}
            />
            <button
              className="btn-primary"
              disabled={!newUsername.trim() || newUserPassword.length < 8}
              onClick={() => void createUser()}
            >
              create
            </button>
          </div>
          {msg && <div className="mt-2 text-sm text-bad">{msg}</div>}
        </div>
      </Section>
    </>
  );
}
