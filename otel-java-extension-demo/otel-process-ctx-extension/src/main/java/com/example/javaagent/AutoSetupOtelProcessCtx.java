/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package com.example.javaagent;

import com.google.auto.service.AutoService;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.resources.Resource;
import java.util.Optional;
import javax.annotation.Nonnull;

@AutoService(AutoConfigurationCustomizerProvider.class)
public class AutoSetupOtelProcessCtx implements AutoConfigurationCustomizerProvider {

  private static final AttributeKey<String> SERVICE_NAME = AttributeKey.stringKey("service.name");
  private static final AttributeKey<String> SERVICE_INSTANCE_ID = AttributeKey.stringKey("service.instance.id");
  private static final AttributeKey<String> SERVICE_VERSION = AttributeKey.stringKey("service.version");
  private static final AttributeKey<String> DEPLOYMENT_ENVIRONMENT_NAME = AttributeKey.stringKey("deployment.environment.name");
  private static final AttributeKey<String> TELEMETRY_SDK_LANGUAGE = AttributeKey.stringKey("telemetry.sdk.language");
  private static final AttributeKey<String> TELEMETRY_SDK_VERSION = AttributeKey.stringKey("telemetry.sdk.version");
  private static final AttributeKey<String> TELEMETRY_SDK_NAME = AttributeKey.stringKey("telemetry.sdk.name");

  @Override
  public void customize(@Nonnull AutoConfigurationCustomizer autoConfiguration) {
    autoConfiguration.addResourceCustomizer(this::setupOtelProcessCtx);
  }

  private Resource setupOtelProcessCtx(Resource resource, ConfigProperties config) {
    OtelProcessCtx.Data data = new OtelProcessCtx.Data(
        Optional.ofNullable(resource.getAttribute(DEPLOYMENT_ENVIRONMENT_NAME)).orElse(""),
        Optional.ofNullable(resource.getAttribute(SERVICE_INSTANCE_ID)).orElse(""),
        Optional.ofNullable(resource.getAttribute(SERVICE_NAME)).orElse(""),
        Optional.ofNullable(resource.getAttribute(SERVICE_VERSION)).orElse(""),
        Optional.ofNullable(resource.getAttribute(TELEMETRY_SDK_LANGUAGE)).orElse(""),
        Optional.ofNullable(resource.getAttribute(TELEMETRY_SDK_VERSION)).orElse(""),
        Optional.ofNullable(resource.getAttribute(TELEMETRY_SDK_NAME)).orElse(""),
        null
    );

    OtelProcessCtx.Result result = OtelProcessCtx.publish(data);
    if (!result.success()) {
      System.err.println("Failed to publish OTEL_CTX: " + result.errorMessage());
    } else {
      System.err.println("Published OTEL_CTX");
    }

    return resource;
  }
}
