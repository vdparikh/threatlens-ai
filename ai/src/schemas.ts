import { z } from "zod";

export const ThreatOutputSchema = z.object({
  /** Major data flows / trust-boundary style rows for executive dashboards (LLM or fallback from flow_graph). */
  architecture_flows: z
    .array(
      z.object({
        boundary_name: z.string(),
        from_component: z.string(),
        to_component: z.string(),
      }),
    )
    .default([]),
  /** Who might attack this system — tailored STRIDE-GPT–style actor table. */
  threat_actor_categories: z
    .array(
      z.object({
        category: z.string(),
        description: z.string(),
        example: z.string(),
      }),
    )
    .default([]),
  threats: z.array(
    z.object({
      id: z.string(),
      stride: z.enum(["S", "T", "R", "I", "D", "E"]),
      title: z.string(),
      description: z.string(),
      severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
      /** Repo paths from the system model that ground this threat (may be empty if unknown). */
      related_paths: z.array(z.string()).default([]),
      /** Short imperative next steps for a developer. */
      immediate_actions: z.array(z.string()).default([]),
      mitigations: z.array(z.string()).default([]),
      /** How to verify the issue or the fix. */
      verification: z.string().default(""),
      references: z
        .array(
          z.object({
            label: z.string(),
            url: z.string().min(1),
          }),
        )
        .default([]),
      /** Step-by-step attacker narrative grounded in the system model (may be empty). */
      attack_scenario: z.string().default(""),
      /** Preconditions or capabilities an attacker needs. */
      prerequisites: z.string().default(""),
      /** Candidate CWE identifiers for triage (e.g. "CWE-285"); not authoritative. */
      cwe_candidates: z.array(z.string()).default([]),
      /** How to detect or monitor for abuse. */
      detection_and_monitoring: z.string().default(""),
      /** Why the assigned severity fits (likelihood). */
      likelihood_rationale: z.string().default(""),
      /** Why the assigned severity fits (impact). */
      impact_rationale: z.string().default(""),
    }),
  ),
  notes: z.string(),
});

export type ThreatOutput = z.infer<typeof ThreatOutputSchema>;
