package com.securetest.ai;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import com.anthropic.core.JsonSchemaLocalValidation;
import com.anthropic.core.JsonValue;
import com.anthropic.errors.AnthropicServiceException;
import com.anthropic.errors.RateLimitException;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.OutputConfig;
import com.anthropic.models.messages.StopReason;
import com.anthropic.models.messages.StructuredMessage;
import com.anthropic.models.messages.StructuredMessageCreateParams;
import com.anthropic.models.messages.StructuredOutputConfig;

import java.util.Locale;

/** Claude via the official Anthropic Java SDK, using structured outputs for the patch. */
public class ClaudeModelClient implements ModelClient {

    private final AnthropicClient client;
    private final String model;
    private final OutputConfig.Effort effort;
    private final boolean refusalFallback;

    public ClaudeModelClient(String apiKey, String baseUrl, String model, String effort, boolean refusalFallback) {
        AnthropicOkHttpClient.Builder b = AnthropicOkHttpClient.builder().apiKey(apiKey);
        if (baseUrl != null && !baseUrl.isBlank()) b.baseUrl(baseUrl);
        this.client = b.build();
        this.model = model;
        this.effort = OutputConfig.Effort.of(effort == null ? "high" : effort.toLowerCase(Locale.ROOT));
        this.refusalFallback = refusalFallback;
    }

    @Override
    public Reply complete(String system, String user) {
        StructuredMessageCreateParams.Builder<AiFixResponse> b = MessageCreateParams.builder()
                .model(model)
                .maxTokens(16000L)
                .system(system)
                .addUserMessage(user)
                .outputConfig(StructuredOutputConfig.<AiFixResponse>builder()
                        .effort(effort)
                        .format(AiFixResponse.class, JsonSchemaLocalValidation.YES)
                        .build());
        if (refusalFallback) {
            // Server-side fallback: if a safety classifier declines, the API retries on a suitable model.
            b.putAdditionalHeader("anthropic-beta", "server-side-fallback-2026-07-01");
            b.putAdditionalBodyProperty("fallbacks", JsonValue.from("default"));
        }
        try {
            StructuredMessage<AiFixResponse> msg = client.messages().create(b.build());
            var raw = msg.rawMessage();
            long in = raw.usage().inputTokens();
            long out = raw.usage().outputTokens();
            String usedModel = raw.model().asString();
            StopReason stop = raw.stopReason().orElse(null);
            if (StopReason.REFUSAL.equals(stop)) {
                String why = msg.stopDetails().flatMap(d -> d.explanation()).orElse("The model declined this request.");
                return new Reply("REFUSED", null, raw.id(), usedModel, in, out, why);
            }
            if (StopReason.MAX_TOKENS.equals(stop)) {
                return new Reply("TRUNCATED", null, raw.id(), usedModel, in, out, "The response hit max_tokens before completing.");
            }
            AiFixResponse fix = msg.content().stream().flatMap(c -> c.text().stream()).map(t -> t.text()).findFirst().orElse(null);
            if (fix == null) return new Reply("ERROR", null, raw.id(), usedModel, in, out, "No structured output in the response.");
            return new Reply("OK", fix, raw.id(), usedModel, in, out, null);
        } catch (RateLimitException e) {
            return new Reply("ERROR", null, null, model, 0, 0, "Rate limited by the Claude API; try again later.");
        } catch (AnthropicServiceException e) {
            return new Reply("ERROR", null, null, model, 0, 0, "Claude API error " + e.statusCode() + ": " + e.getMessage());
        } catch (RuntimeException e) {
            return new Reply("ERROR", null, null, model, 0, 0, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    @Override public String provider() { return "anthropic"; }
    @Override public String model() { return model; }
}
