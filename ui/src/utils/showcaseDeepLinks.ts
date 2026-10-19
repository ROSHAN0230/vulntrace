/**
 * VulnTrace Showcase Deep-Link Query Normalization Engine.
 * 
 * Normalizes case query parameters by converting hyphens to underscores,
 * handling case-insensitivity, and resolving legacy aliases to primary showcase IDs.
 */

export type ShowcaseCaseId =
  | 'contextual_reasoning'
  | 'case_rw_04'
  | 'flasgger_external'
  | 'naive_comparison'
  | 'tavily_intel';

/**
 * Resolves a showcase case ID from a query string, URL search parameters, or raw case string.
 * Converts hyphens to underscores before matching and preserves case-insensitive alias lookups.
 * 
 * @param queryOrParam E.g. "?view=showcase&case=CASE-RW-01", "CASE-RW-01", "synth-01", etc.
 * @returns The resolved ShowcaseCaseId (defaults to 'contextual_reasoning')
 */
export function resolveCaseFromQuery(queryOrParam?: string | null): ShowcaseCaseId {
  if (!queryOrParam) return 'contextual_reasoning';

  let rawCase = queryOrParam.trim();
  if (rawCase.includes('=')) {
    const search = rawCase.startsWith('?') ? rawCase : `?${rawCase}`;
    const params = new URLSearchParams(search);
    const paramVal = params.get('case');
    if (paramVal) {
      rawCase = paramVal;
    }
  }

  // Normalize: trim, lowercase, and convert hyphens to underscores
  const caseParam = rawCase.toLowerCase().replace(/-/g, '_');

  if (
    caseParam === 'case_rw_04' ||
    caseParam === 'rw_04' ||
    caseParam === 'repo_cloud_config' ||
    caseParam === 'rw04'
  ) {
    return 'case_rw_04';
  }

  if (
    caseParam === 'flasgger_external' ||
    caseParam === 'flasgger' ||
    caseParam === 'case_rw_01' ||
    caseParam === 'rw_01' ||
    caseParam === 'rw01'
  ) {
    return 'flasgger_external';
  }

  if (
    caseParam === 'naive_comparison' ||
    caseParam === 'naive' ||
    caseParam === 'comparison' ||
    caseParam === 'phase5'
  ) {
    return 'naive_comparison';
  }

  if (
    caseParam === 'tavily_intel' ||
    caseParam === 'tavily' ||
    caseParam === 'intel' ||
    caseParam === 'phase6'
  ) {
    return 'tavily_intel';
  }

  if (
    caseParam === 'contextual_reasoning' ||
    caseParam === 'synth_01' ||
    caseParam === 'synth01' ||
    caseParam === 'contextual'
  ) {
    return 'contextual_reasoning';
  }

  return 'contextual_reasoning';
}

/**
 * Resolves the initial showcase case ID in the browser from `window.location.search`.
 */
export function resolveInitialCaseId(): ShowcaseCaseId {
  if (typeof window !== 'undefined') {
    return resolveCaseFromQuery(window.location.search);
  }
  return 'contextual_reasoning';
}
