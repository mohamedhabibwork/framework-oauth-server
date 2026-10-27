import type { Scope, ScopeRegistry } from './types';

/**
 * In-memory scope registry: the catalog of scopes an authorization server
 * advertises and validates requests against. Registration is explicit and
 * additive; unknown names are reported, never silently accepted (ADR-11).
 */
export class InMemoryScopeRegistry implements ScopeRegistry {
  private readonly scopes = new Map<string, Scope>();

  constructor(initial: readonly Scope[] = []) {
    for (const scope of initial) this.register(scope);
  }

  register(scope: Scope): void {
    this.scopes.set(scope.name, scope);
  }

  all(): readonly Scope[] {
    return [...this.scopes.values()];
  }

  /** Returns the unknown names (empty when every name is registered). */
  validate(names: readonly string[]): string[] {
    return names.filter((name) => !this.scopes.has(name));
  }
}

/**
 * Expands names with the scopes they imply, transitively. De-duplicates while
 * preserving the order scopes were first seen, so callers can grant a superset
 * (`read` implying `read:public`) deterministically.
 */
export function expandScopes(registry: ScopeRegistry, names: readonly string[]): readonly string[] {
  const byName = new Map(registry.all().map((scope) => [scope.name, scope]));
  const expanded: string[] = [];
  const seen = new Set<string>();
  const visit = (name: string): void => {
    if (seen.has(name)) return;
    seen.add(name);
    expanded.push(name);
    for (const implied of byName.get(name)?.implies ?? []) visit(implied);
  };
  for (const name of names) visit(name);
  return expanded;
}
