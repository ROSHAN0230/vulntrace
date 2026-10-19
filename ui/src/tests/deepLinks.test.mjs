import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveCaseFromQuery } from '../utils/showcaseDeepLinks.ts';

test('1. ?case=CASE-RW-01 opens flasgger_external (Flasgger Vulnerable Commit)', () => {
  const result = resolveCaseFromQuery('?case=CASE-RW-01');
  assert.equal(result, 'flasgger_external');
});

test('2. ?case=CASE-RW-04 opens case_rw_04 (Cloud Config Service)', () => {
  const result = resolveCaseFromQuery('?case=CASE-RW-04');
  assert.equal(result, 'case_rw_04');
});

test('3. ?case=SYNTH-01 opens contextual_reasoning (Custom AppSafeLoader)', () => {
  const result = resolveCaseFromQuery('?case=SYNTH-01');
  assert.equal(result, 'contextual_reasoning');
});

test('4. All five primary showcase deep links remain fully functional', () => {
  assert.equal(resolveCaseFromQuery('?view=showcase&case=contextual_reasoning'), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery('?view=showcase&case=case_rw_04'), 'case_rw_04');
  assert.equal(resolveCaseFromQuery('?view=showcase&case=flasgger_external'), 'flasgger_external');
  assert.equal(resolveCaseFromQuery('?view=showcase&case=naive_comparison'), 'naive_comparison');
  assert.equal(resolveCaseFromQuery('?view=showcase&case=tavily_intel'), 'tavily_intel');
});

test('5. Case-insensitivity and hyphen-to-underscore normalization work seamlessly', () => {
  assert.equal(resolveCaseFromQuery('?case=case-rw-01'), 'flasgger_external');
  assert.equal(resolveCaseFromQuery('?case=case-rw-04'), 'case_rw_04');
  assert.equal(resolveCaseFromQuery('?case=synth-01'), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery('?case=NaIvE-CoMpArIsOn'), 'naive_comparison');
  assert.equal(resolveCaseFromQuery('?case=TAVILY-INTEL'), 'tavily_intel');
});

test('6. Existing legacy aliases continue to resolve accurately', () => {
  // Flasgger aliases
  assert.equal(resolveCaseFromQuery('?case=flasgger'), 'flasgger_external');
  assert.equal(resolveCaseFromQuery('?case=case_rw_01'), 'flasgger_external');
  assert.equal(resolveCaseFromQuery('?case=rw_01'), 'flasgger_external');
  assert.equal(resolveCaseFromQuery('?case=rw-01'), 'flasgger_external');
  assert.equal(resolveCaseFromQuery('?case=rw01'), 'flasgger_external');

  // Cloud Config Microservice aliases
  assert.equal(resolveCaseFromQuery('?case=repo_cloud_config'), 'case_rw_04');
  assert.equal(resolveCaseFromQuery('?case=repo-cloud-config'), 'case_rw_04');
  assert.equal(resolveCaseFromQuery('?case=case_rw_04'), 'case_rw_04');
  assert.equal(resolveCaseFromQuery('?case=rw_04'), 'case_rw_04');
  assert.equal(resolveCaseFromQuery('?case=rw-04'), 'case_rw_04');
  assert.equal(resolveCaseFromQuery('?case=rw04'), 'case_rw_04');

  // Naive comparison aliases
  assert.equal(resolveCaseFromQuery('?case=naive'), 'naive_comparison');
  assert.equal(resolveCaseFromQuery('?case=comparison'), 'naive_comparison');
  assert.equal(resolveCaseFromQuery('?case=phase5'), 'naive_comparison');

  // Tavily Threat Intelligence aliases
  assert.equal(resolveCaseFromQuery('?case=tavily'), 'tavily_intel');
  assert.equal(resolveCaseFromQuery('?case=intel'), 'tavily_intel');
  assert.equal(resolveCaseFromQuery('?case=phase6'), 'tavily_intel');

  // Contextual reasoning aliases
  assert.equal(resolveCaseFromQuery('?case=synth_01'), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery('?case=synth01'), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery('?case=contextual'), 'contextual_reasoning');
});

test('7. Empty, null, undefined, or unrecognized query strings safely default to contextual_reasoning', () => {
  assert.equal(resolveCaseFromQuery(null), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery(undefined), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery(''), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery('?view=showcase'), 'contextual_reasoning');
  assert.equal(resolveCaseFromQuery('?case=unknown_unregistered_id'), 'contextual_reasoning');
});
