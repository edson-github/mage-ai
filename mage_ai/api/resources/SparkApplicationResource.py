from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.api.resources.mixins.spark import SparkApplicationChild
from mage_ai.services.spark.models.applications import Application
from mage_ai.shared.hash import index_by


class SparkApplicationResource(GenericResource, SparkApplicationChild):
    @classmethod
    async def get_model(cls, pk):
        return Application.load(id=pk)

    @classmethod
    async def collection(cls, _query, _meta, user, **kwargs):
        applications = await cls.build_api().applications()
        mapping = index_by(lambda x: x.id, applications)

        if applications_cache := Application.get_applications_from_cache():
            for application in applications_cache.values():
                if application.calculated_id() in mapping:
                    continue
                applications.append(application)
                mapping[application.calculated_id()] = application

        return cls.build_result_set(applications, user, **kwargs)
