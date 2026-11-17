"""GRAF helpers and mutation core.

Package imports stay lightweight so skeleton generation and offline pool
bookkeeping do not require a parser or a live target driver.
"""

from importlib import import_module

_EXPORTS = {
    "EnterpriseFeedbackMonitor": "feedback",
    "EnterpriseMutationEngine": "engine",
    "GraphStats": "model",
    "GraphSeedSpec": "seed_profiles",
    "IR_VERSION": "ir",
    "MutationCandidate": "ir",
    "MutationDirective": "model",
    "MutationIRCodec": "ir",
    "MutationIRCodecError": "ir",
    "MutationIRCompileError": "ir",
    "MutationIRCompiler": "ir",
    "MutationProgram": "ir",
    "MutationResult": "model",
    "MutationStatus": "model",
    "OperatorKind": "model",
    "QueryIR": "ir",
    "QueryIRBuilder": "ir",
    "SchemaView": "model",
    "SeedPortfolioScheduler": "seed_profiles",
    "ValidationPipeline": "validation",
    "ValidationResult": "model",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str):
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(name)
    value = getattr(import_module(f".{module}", __name__), name)
    globals()[name] = value
    return value
