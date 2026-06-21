"""
Custom exception hierarchy.
"""
from typing import Optional

class PipelineBaseException(Exception):
    def __init__(
        self,
        message: str,
        correlation_id: str,
        stage_name: str,
        assessment_run_id: str,
        **kwargs: str
    ):
        self.message = message
        self.correlation_id = correlation_id
        self.stage_name = stage_name
        self.assessment_run_id = assessment_run_id
        self.extra = kwargs
        super().__init__(self.message)

# QuestionnaireExceptions
class QuestionnaireException(PipelineBaseException): pass
class QuestionnaireLoadException(QuestionnaireException): pass
class QuestionnaireValidationException(QuestionnaireException): pass
class MissingResponseException(QuestionnaireException): pass

# WeightConfigExceptions
class WeightConfigException(PipelineBaseException): pass
class WeightLoadException(WeightConfigException): pass
class WeightFrozenException(WeightConfigException): pass
class ThresholdOverrideException(WeightConfigException): pass

# ScoringExceptions
class ScoringException(PipelineBaseException): pass
class ScoreComputationException(ScoringException): pass
class CategoryFloorException(ScoringException): pass
class DecimalPrecisionException(ScoringException): pass

# ExternalDataExceptions
class ExternalDataException(PipelineBaseException): pass
class StaleExternalDataException(ExternalDataException): pass
class ExternalAPIException(ExternalDataException): pass
class SignalBlendException(ExternalDataException): pass

# ReportExceptions
class ReportException(PipelineBaseException): pass
class ReportGenerationException(ReportException): pass
class ReportIntegrityException(ReportException): pass
class FontLoadException(ReportException): pass

# ExportExceptions
class ExportException(PipelineBaseException): pass
class NullRateViolationException(ExportException): pass
class RowCountViolationException(ExportException): pass
class FileWriteException(ExportException): pass

# AuditExceptions
class AuditException(PipelineBaseException): pass
class HealthCheckFailedException(AuditException): pass
class LineageBreachException(AuditException): pass
class CheckpointCorruptException(AuditException): pass
