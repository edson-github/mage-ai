from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.api.resources.mixins.spark import SparkApplicationChild


class SparkStageAttemptResource(GenericResource, SparkApplicationChild):
    @classmethod
    async def collection(cls, _query, _meta, user, **kwargs):
        parent_model = kwargs.get('parent_model')

        return cls.build_result_set(
            await cls.build_api().stage_attempts(stage_id=parent_model.id),
            user,
            **kwargs
        )

    @classmethod
    async def member(cls, pk, user, **kwargs):
        parent_model = kwargs.get('parent_model')

        return cls(
            await cls.build_api().stage_attempt(
                attempt_id=pk, stage_id=parent_model.id
            ),
            user,
            **kwargs
        )
