import path from "node:path";
import type { ChatType } from "../channels/chat-type.js";
import { normalizeChatType } from "../channels/chat-type.js";
import type { OpenClawConfig } from "../config/config.js";
import { listBindings } from "../routing/bindings.js";
import { resolveAgentRoute } from "../routing/resolve-route.js";
import { normalizeAccountId, normalizeAgentId } from "../routing/session-key.js";
import { resolveUserPath } from "../utils.js";

export type TeamWorkspaceConfig = {
  path: string;
};

export type ResolvedTeamWorkspace = {
  name: string;
  path: string;
};

type AgentEntry = NonNullable<NonNullable<OpenClawConfig["agents"]>["list"]>[number];
type RouteBinding = ReturnType<typeof listBindings>[number];
type MatchedBy = ReturnType<typeof resolveAgentRoute>["matchedBy"];

type NormalizedPeerConstraint =
  | { state: "none" }
  | { state: "invalid" }
  | { state: "valid"; kind: ChatType; id: string };

type RoutePeerInput = {
  kind?: string | null;
  id?: string | null;
};

function resolveAgentEntry(cfg: OpenClawConfig, agentId: string): AgentEntry | undefined {
  const normalized = normalizeAgentId(agentId);
  const list = Array.isArray(cfg.agents?.list) ? cfg.agents?.list : [];
  return list.find((entry) => normalizeAgentId(entry.id) === normalized);
}

function normalizeTeamWorkspaceValue(value: unknown): TeamWorkspaceConfig | null {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? { path: trimmed } : null;
  }
  if (!value || typeof value !== "object") {
    return null;
  }
  const rawPath =
    typeof (value as { path?: unknown }).path === "string"
      ? (value as { path: string }).path.trim()
      : "";
  if (!rawPath) {
    return null;
  }
  return {
    path: rawPath,
  };
}

function normalizePeerConstraint(peer: RoutePeerInput | undefined): NormalizedPeerConstraint {
  if (!peer) {
    return { state: "none" };
  }
  const kind = normalizeChatType(peer.kind ?? undefined);
  const id = String(peer.id ?? "").trim();
  if (!kind || !id) {
    return { state: "invalid" };
  }
  return { state: "valid", kind, id };
}

function peerKindMatches(bindingKind: ChatType, scopeKind: ChatType): boolean {
  if (bindingKind === scopeKind) {
    return true;
  }
  const both = new Set([bindingKind, scopeKind]);
  return both.has("group") && both.has("channel");
}

function isAccountPatternMatch(rawPattern: unknown, accountId: string): boolean {
  const pattern = typeof rawPattern === "string" ? rawPattern.trim() : "";
  if (pattern === "*") {
    return true;
  }
  return normalizeAccountId(pattern) === accountId;
}

function hasGuildConstraint(match: RouteBinding["match"]): boolean {
  return String(match?.guildId ?? "").trim().length > 0;
}

function hasTeamConstraint(match: RouteBinding["match"]): boolean {
  return String(match?.teamId ?? "").trim().length > 0;
}

function hasRolesConstraint(match: RouteBinding["match"]): boolean {
  return Array.isArray(match?.roles) && match.roles.length > 0;
}

function resolveBindingTier(
  match: RouteBinding["match"],
): Exclude<MatchedBy, "default" | "binding.peer.parent"> | null {
  const peer = normalizePeerConstraint(
    match?.peer ? { kind: String(match.peer.kind), id: String(match.peer.id) } : undefined,
  );
  if (peer.state === "valid") {
    return "binding.peer";
  }
  if (hasGuildConstraint(match) && hasRolesConstraint(match)) {
    return "binding.guild+roles";
  }
  if (hasGuildConstraint(match) && !hasRolesConstraint(match)) {
    return "binding.guild";
  }
  if (hasTeamConstraint(match)) {
    return "binding.team";
  }
  const accountPattern = String(match?.accountId ?? "").trim();
  return accountPattern === "*" ? "binding.channel" : "binding.account";
}

function matchesBindingScope(params: {
  bindingMatch: RouteBinding["match"];
  scopePeer: RoutePeerInput | null;
  guildId: string;
  teamId: string;
  memberRoleIds: Set<string>;
}): boolean {
  const peer = normalizePeerConstraint(
    params.bindingMatch?.peer
      ? {
          kind: String(params.bindingMatch.peer.kind),
          id: String(params.bindingMatch.peer.id),
        }
      : undefined,
  );
  if (peer.state === "invalid") {
    return false;
  }
  if (peer.state === "valid") {
    const scopeKind = normalizeChatType(params.scopePeer?.kind ?? undefined);
    const scopeId = String(params.scopePeer?.id ?? "").trim();
    if (!scopeKind || !scopeId || !peerKindMatches(peer.kind, scopeKind) || scopeId !== peer.id) {
      return false;
    }
  }
  const matchGuildId = String(params.bindingMatch?.guildId ?? "").trim();
  if (matchGuildId && matchGuildId !== params.guildId) {
    return false;
  }
  const matchTeamId = String(params.bindingMatch?.teamId ?? "").trim();
  if (matchTeamId && matchTeamId !== params.teamId) {
    return false;
  }
  const matchRoles = Array.isArray(params.bindingMatch?.roles)
    ? params.bindingMatch.roles
    : undefined;
  if (matchRoles && matchRoles.length > 0) {
    for (const role of matchRoles) {
      if (params.memberRoleIds.has(role)) {
        return true;
      }
    }
    return false;
  }
  return true;
}

function resolveMatchedRouteBinding(params: {
  cfg: OpenClawConfig;
  agentId: string;
  channel: string;
  accountId?: string | null;
  peer?: RoutePeerInput | null;
  parentPeer?: RoutePeerInput | null;
  guildId?: string | null;
  teamId?: string | null;
  memberRoleIds?: string[];
}): RouteBinding | undefined {
  const channel = String(params.channel ?? "")
    .trim()
    .toLowerCase();
  if (!channel) {
    return undefined;
  }
  const accountId = normalizeAccountId(params.accountId ?? undefined);
  const guildId = String(params.guildId ?? "").trim();
  const teamId = String(params.teamId ?? "").trim();
  const memberRoleIds = new Set(Array.isArray(params.memberRoleIds) ? params.memberRoleIds : []);
  const peer = params.peer?.kind && params.peer?.id ? params.peer : undefined;
  const parentPeer =
    params.parentPeer?.kind && params.parentPeer?.id ? params.parentPeer : undefined;

  const route = resolveAgentRoute({
    cfg: params.cfg,
    channel,
    accountId,
    peer: peer
      ? {
          kind: normalizeChatType(peer.kind ?? undefined) ?? "direct",
          id: String(peer.id),
        }
      : undefined,
    parentPeer: parentPeer
      ? {
          kind: normalizeChatType(parentPeer.kind ?? undefined) ?? "channel",
          id: String(parentPeer.id),
        }
      : undefined,
    guildId,
    teamId,
    memberRoleIds: Array.from(memberRoleIds),
  });
  if (route.matchedBy === "default") {
    return undefined;
  }
  if (normalizeAgentId(route.agentId) !== normalizeAgentId(params.agentId)) {
    return undefined;
  }

  for (const binding of listBindings(params.cfg)) {
    if (normalizeAgentId(binding.agentId) !== normalizeAgentId(params.agentId)) {
      continue;
    }
    const match = binding.match;
    if (
      !match ||
      String(match.channel ?? "")
        .trim()
        .toLowerCase() !== channel
    ) {
      continue;
    }
    if (!isAccountPatternMatch(match.accountId, accountId)) {
      continue;
    }

    const tier = resolveBindingTier(match);
    if (!tier) {
      continue;
    }

    const scopePeer =
      route.matchedBy === "binding.peer.parent"
        ? (parentPeer ?? null)
        : route.matchedBy === "binding.peer"
          ? (peer ?? null)
          : (peer ?? null);

    const expectedTier =
      route.matchedBy === "binding.peer.parent" ? "binding.peer" : route.matchedBy;
    if (tier !== expectedTier) {
      continue;
    }
    if (
      !matchesBindingScope({
        bindingMatch: match,
        scopePeer,
        guildId,
        teamId,
        memberRoleIds,
      })
    ) {
      continue;
    }

    return binding;
  }

  return undefined;
}

export function resolveAgentPersonDir(cfg: OpenClawConfig, agentId: string): string | undefined {
  const entry = resolveAgentEntry(cfg, agentId);
  const raw =
    typeof (entry as { personDir?: unknown } | undefined)?.personDir === "string"
      ? ((entry as { personDir?: string }).personDir ?? "").trim()
      : "";
  return raw ? resolveUserPath(raw) : undefined;
}

export function listAgentTeamWorkspaces(
  cfg: OpenClawConfig,
  agentId: string,
): Record<string, ResolvedTeamWorkspace> {
  const entry = resolveAgentEntry(cfg, agentId);
  const raw = (entry as { teamWorkspaces?: unknown } | undefined)?.teamWorkspaces;
  if (!raw || typeof raw !== "object") {
    return {};
  }
  const resolved: Record<string, ResolvedTeamWorkspace> = {};
  for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
    const normalizedName = name.trim();
    const normalizedValue = normalizeTeamWorkspaceValue(value);
    if (!normalizedName || !normalizedValue) {
      continue;
    }
    resolved[normalizedName] = {
      name: normalizedName,
      path: resolveUserPath(normalizedValue.path),
    };
  }
  return resolved;
}

export function resolveAgentTeamWorkspace(
  cfg: OpenClawConfig,
  agentId: string,
  teamWorkspaceName: string | undefined | null,
): ResolvedTeamWorkspace | undefined {
  const name = String(teamWorkspaceName ?? "").trim();
  if (!name) {
    return undefined;
  }
  return listAgentTeamWorkspaces(cfg, agentId)[name];
}

function resolveBindingTeamWorkspace(params: {
  cfg: OpenClawConfig;
  agentId: string;
  channel: string;
  accountId?: string | null;
  peer?: RoutePeerInput | null;
  parentPeer?: RoutePeerInput | null;
  guildId?: string | null;
  teamId?: string | null;
  memberRoleIds?: string[];
}): { matched: boolean; teamWorkspaceName?: string } {
  const matchedBinding = resolveMatchedRouteBinding(params);
  if (!matchedBinding) {
    return { matched: false };
  }
  const teamWorkspaceName =
    typeof (matchedBinding as { teamWorkspace?: unknown }).teamWorkspace === "string"
      ? ((matchedBinding as { teamWorkspace?: string }).teamWorkspace ?? "").trim()
      : "";
  if (!teamWorkspaceName) {
    return { matched: true };
  }
  return {
    matched: true,
    teamWorkspaceName,
  };
}

export function resolveEffectiveWorkspaceDir(params: {
  cfg: OpenClawConfig;
  agentId: string;
  fallbackWorkspaceDir: string;
  sessionEntry?: { teamWorkspace?: string } | null;
  routeContext?: {
    channel?: string;
    accountId?: string | null;
    peer?: RoutePeerInput | null;
    parentPeer?: RoutePeerInput | null;
    guildId?: string | null;
    teamId?: string | null;
    memberRoleIds?: string[];
  } | null;
}): {
  workspaceDir: string;
  teamWorkspace?: ResolvedTeamWorkspace;
  /**
   * undefined = no route binding was matched with current route context
   * null = a route binding was matched but no valid teamWorkspace should be applied
   * string = a valid routed teamWorkspace name was resolved
   */
  routedTeamWorkspaceName?: string | null;
} {
  const persistedTeam = String(params.sessionEntry?.teamWorkspace ?? "").trim();
  const routed = params.routeContext
    ? resolveBindingTeamWorkspace({
        cfg: params.cfg,
        agentId: params.agentId,
        channel: params.routeContext.channel ?? "",
        accountId: params.routeContext.accountId,
        peer: params.routeContext.peer,
        parentPeer: params.routeContext.parentPeer,
        guildId: params.routeContext.guildId,
        teamId: params.routeContext.teamId,
        memberRoleIds: params.routeContext.memberRoleIds,
      })
    : { matched: false as const };

  const effectiveTeamName = routed.matched ? (routed.teamWorkspaceName ?? "") : persistedTeam;
  const teamWorkspace = resolveAgentTeamWorkspace(params.cfg, params.agentId, effectiveTeamName);
  if (teamWorkspace) {
    return {
      workspaceDir: path.resolve(teamWorkspace.path),
      teamWorkspace,
      routedTeamWorkspaceName: routed.matched ? teamWorkspace.name : undefined,
    };
  }

  return {
    workspaceDir: path.resolve(params.fallbackWorkspaceDir),
    routedTeamWorkspaceName: routed.matched ? null : undefined,
  };
}
