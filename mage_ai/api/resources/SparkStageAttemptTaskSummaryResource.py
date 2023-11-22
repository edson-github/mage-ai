from mage_ai.api.errors import ApiError
from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.api.resources.mixins.spark import SparkApplicationChild


class SparkStageAttemptTaskSummaryResource(GenericResource, SparkApplicationChild):
    @classmethod
    async def member(cls, pk, user, **kwargs):
        parent_model = kwargs.get('parent_model')
        if parent_model is None:
            error = ApiError(ApiError.RESOURCE_NOT_FOUND)
            error.message = 'Stage not found.'
            raise error

        return cls(
            await cls.build_api().stage_attempt_task_summary(
                attempt_id=pk, stage_id=parent_model.id
            ),
            user,
            **kwargs
        )
