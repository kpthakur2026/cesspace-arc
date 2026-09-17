import {
  PolicyOutcome,
  type PolicyEffect,
  type PolicyEvaluationContext,
  type PolicyDecisionResult,
  type PolicyRule,
} from '@cesspace-arc/protocol';

/**
 * Interface definition for the CesSpace ARC Policy Engine.
 * Implementation target: RC-04.
 */
export interface IPolicyEngine {
  evaluate(context: PolicyEvaluationContext): Promise<PolicyDecisionResult>;
  loadPolicy(rules: PolicyRule[]): void;
}

export { PolicyOutcome, type PolicyEffect, type PolicyEvaluationContext, type PolicyDecisionResult, type PolicyRule };
