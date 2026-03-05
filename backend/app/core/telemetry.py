"""
OfSec V3 — OpenTelemetry Instrumentation
==========================================
Distributed tracing for backend services.
"""

import structlog
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

from app.config import settings

logger = structlog.get_logger()


def setup_telemetry() -> None:
    """Initialize OpenTelemetry tracing."""
    resource = Resource.create({
        "service.name": settings.OTEL_SERVICE_NAME,
        "service.version": settings.VERSION,
        "deployment.environment": settings.ENVIRONMENT,
    })

    provider = TracerProvider(resource=resource)

    # In dev, export to console; in prod, use OTLP exporter
    if settings.DEBUG:
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
    else:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            exporter = OTLPSpanExporter(endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT)
            processor = SimpleSpanProcessor(exporter)
        except ImportError:
            logger.warning("ofsec.telemetry.otlp_unavailable", msg="Falling back to console exporter")
            processor = SimpleSpanProcessor(ConsoleSpanExporter())

    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    logger.info("ofsec.telemetry.initialized", service=settings.OTEL_SERVICE_NAME)


def get_tracer(name: str = "ofsec") -> trace.Tracer:
    """Get a named tracer for custom spans."""
    return trace.get_tracer(name)
