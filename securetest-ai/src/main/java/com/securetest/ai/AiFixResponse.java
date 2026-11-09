package com.securetest.ai;

import com.fasterxml.jackson.annotation.JsonPropertyDescription;

/** Structured output requested from the model (JSON schema derived from this class). */
public class AiFixResponse {

    @JsonPropertyDescription("First line (1-based, inclusive) of the original code to replace. Use 0 when no safe in-window fix exists.")
    public int startLine;

    @JsonPropertyDescription("Last line (1-based, inclusive) of the original code to replace. Use 0 when no safe in-window fix exists.")
    public int endLine;

    @JsonPropertyDescription("Replacement source text for lines startLine..endLine, with original indentation. Empty when startLine is 0.")
    public String replacement;

    @JsonPropertyDescription("Plain-language explanation for the reviewer: what changed, why it fixes the finding, and any follow-up needed.")
    public String explanation;

    @JsonPropertyDescription("One of: high, medium, low - how confident you are that the patch is correct and complete.")
    public String confidence;

    @JsonPropertyDescription("Behaviour changes, new imports or dependencies, or tests the reviewer should add. Empty if none.")
    public String reviewNotes;
}
