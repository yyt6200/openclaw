import path from "node:path";
import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import { resolveUserPath } from "../utils.js";
import {
  listAgentTeamWorkspaces,
  resolveAgentPersonDir,
  resolveEffectiveWorkspaceDir,
} from "./team-workspaces.js";

describe("team workspaces", () => {
  it("resolves personDir and named team workspaces", () => {
    const cfg: OpenClawConfig = {
      agents: {
        list: [
          {
            id: "main",
            personDir: "~/people/main",
            teamWorkspaces: {
              alpha: "~/teams/alpha",
              beta: { path: "~/teams/beta" },
            },
          },
        ],
      },
    };

    expect(resolveAgentPersonDir(cfg, "main")).toBe(resolveUserPath("~/people/main"));
    expect(listAgentTeamWorkspaces(cfg, "main")).toEqual({
      alpha: {
        name: "alpha",
        path: resolveUserPath("~/teams/alpha"),
      },
      beta: {
        name: "beta",
        path: resolveUserPath("~/teams/beta"),
      },
    });
  });

  it("uses routed teamWorkspace when the matched binding selects one", () => {
    const cfg: OpenClawConfig = {
      agents: {
        list: [
          {
            id: "main",
            workspace: "/fallback",
            teamWorkspaces: {
              alpha: "/teams/alpha",
            },
          },
        ],
      },
      bindings: [
        {
          agentId: "main",
          teamWorkspace: "alpha",
          match: { channel: "signal", accountId: "acct-1" },
        },
      ],
    };

    const resolved = resolveEffectiveWorkspaceDir({
      cfg,
      agentId: "main",
      fallbackWorkspaceDir: "/fallback",
      routeContext: {
        channel: "signal",
        accountId: "acct-1",
      },
    });

    expect(resolved.workspaceDir).toBe(path.resolve("/teams/alpha"));
    expect(resolved.teamWorkspace?.name).toBe("alpha");
    expect(resolved.routedTeamWorkspaceName).toBe("alpha");
  });

  it("falls back to persisted teamWorkspace when no route binding matches", () => {
    const cfg: OpenClawConfig = {
      agents: {
        list: [
          {
            id: "main",
            workspace: "/fallback",
            teamWorkspaces: {
              alpha: "/teams/alpha",
            },
          },
        ],
      },
    };

    const resolved = resolveEffectiveWorkspaceDir({
      cfg,
      agentId: "main",
      fallbackWorkspaceDir: "/fallback",
      sessionEntry: { teamWorkspace: "alpha" },
      routeContext: {
        channel: "signal",
        accountId: "acct-1",
      },
    });

    expect(resolved.workspaceDir).toBe(path.resolve("/teams/alpha"));
    expect(resolved.teamWorkspace?.name).toBe("alpha");
    expect(resolved.routedTeamWorkspaceName).toBeUndefined();
  });

  it("clears persisted teamWorkspace when a matched binding omits teamWorkspace", () => {
    const cfg: OpenClawConfig = {
      agents: {
        list: [
          {
            id: "main",
            workspace: "/fallback",
            teamWorkspaces: {
              alpha: "/teams/alpha",
            },
          },
        ],
      },
      bindings: [
        {
          agentId: "main",
          match: { channel: "signal", accountId: "acct-1" },
        },
      ],
    };

    const resolved = resolveEffectiveWorkspaceDir({
      cfg,
      agentId: "main",
      fallbackWorkspaceDir: "/fallback",
      sessionEntry: { teamWorkspace: "alpha" },
      routeContext: {
        channel: "signal",
        accountId: "acct-1",
      },
    });

    expect(resolved.workspaceDir).toBe(path.resolve("/fallback"));
    expect(resolved.teamWorkspace).toBeUndefined();
    expect(resolved.routedTeamWorkspaceName).toBeNull();
  });

  it("honors parent peer routing tier for threaded conversations", () => {
    const cfg: OpenClawConfig = {
      agents: {
        list: [
          {
            id: "main",
            workspace: "/fallback",
            teamWorkspaces: {
              alpha: "/teams/alpha",
            },
          },
        ],
      },
      bindings: [
        {
          agentId: "main",
          teamWorkspace: "alpha",
          match: {
            channel: "discord",
            accountId: "default",
            peer: { kind: "channel", id: "parent-channel" },
          },
        },
      ],
    };

    const resolved = resolveEffectiveWorkspaceDir({
      cfg,
      agentId: "main",
      fallbackWorkspaceDir: "/fallback",
      routeContext: {
        channel: "discord",
        accountId: "default",
        peer: { kind: "channel", id: "thread-channel" },
        parentPeer: { kind: "channel", id: "parent-channel" },
      },
    });

    expect(resolved.workspaceDir).toBe(path.resolve("/teams/alpha"));
    expect(resolved.teamWorkspace?.name).toBe("alpha");
  });
});
