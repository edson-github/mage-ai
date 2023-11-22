from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.api.resources.mixins.spark import SparkApplicationChild


class SparkThreadResource(GenericResource, SparkApplicationChild):
    @classmethod
    async def collection(cls, _query, _meta, user, **kwargs):
        parent_model = kwargs.get('parent_model')

        return cls.build_result_set(
            await cls.build_api().threads(executor_id=parent_model.id),
            user,
            **kwargs
        )
