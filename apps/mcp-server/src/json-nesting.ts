/**
 * Frozen RC-08 inbound JSON nesting ceiling.
 *
 * A root object or array has depth 1. Each object or array contained within
 * another object or array increases the depth by 1. Primitive values do not
 * increase depth. The traversal is iterative so adversarial nesting cannot
 * consume the JavaScript call stack, and it returns as soon as depth 11 is
 * observed.
 */
export const MAX_JSON_NESTING_DEPTH = 10;

/** Returns true when an inbound JSON value exceeds the frozen nesting ceiling. */
export function exceedsMaxJsonNestingDepth(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false;

  const pending: Array<{ value: object; depth: number }> = [{ value, depth: 1 }];
  const visited = new WeakSet<object>();

  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    if (current.depth > MAX_JSON_NESTING_DEPTH) return true;
    if (visited.has(current.value)) continue;
    visited.add(current.value);

    for (const child of Object.values(current.value)) {
      if (child !== null && typeof child === 'object') {
        const childDepth = current.depth + 1;
        if (childDepth > MAX_JSON_NESTING_DEPTH) return true;
        pending.push({ value: child, depth: childDepth });
      }
    }
  }

  return false;
}
