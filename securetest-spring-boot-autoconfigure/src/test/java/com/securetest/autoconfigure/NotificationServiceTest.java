package com.securetest.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securetest.autoconfigure.service.NotificationService;
import com.securetest.autoconfigure.support.SecretResolver;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class NotificationServiceTest {

    @Test
    void sendsRedactedEmailOnlyForSubscribedEvents() {
        SecureTestProperties props = new SecureTestProperties();
        props.getNotifications().getEmail().setEnabled(true);
        props.getNotifications().getEmail().setTo(List.of("secops@example.com"));
        List<String[]> sent = new CopyOnWriteArrayList<>();
        NotificationService n = new NotificationService(props, new SecretResolver(new MockEnvironment(), null), new ObjectMapper(),
                (from, to, subject, body) -> sent.add(new String[] {from, String.join(",", to), subject, body}));

        n.publish("scan.completed", "not subscribed", Map.of());
        n.publish("finding.critical", "Critical finding: token=abcdef123456 leaked", Map.of("jobId", "S-1"));

        await().atMost(5, TimeUnit.SECONDS).until(() -> sent.size() == 1);
        assertThat(sent.get(0)[1]).isEqualTo("secops@example.com");
        assertThat(sent.get(0)[2]).startsWith("[SecureTest] finding.critical");
        assertThat(sent.get(0)[3]).doesNotContain("abcdef123456").contains("S-1");
        assertThat(n.emailAvailable()).isTrue();
        n.shutdown();
    }
}
