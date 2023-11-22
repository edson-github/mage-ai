from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.api.resources.mixins.spark import SparkApplicationChild


class SparkJobResource(GenericResource, SparkApplicationChild):
    @classmethod
    async def collection(cls, _query, _meta, user, **kwargs):
        return cls.build_result_set(await cls.build_api().jobs(), user, **kwargs)

    @classmethod
    async def member(cls, pk, user, **kwargs):
        query_arg = kwargs.get('query')

        application_id = cls.application_calculated_id_from_query(query_arg)

        application_spark_ui_url = query_arg.get('application_spark_ui_url', [])
        if application_spark_ui_url:
            application_spark_ui_url = application_spark_ui_url[0]

        return cls(
            await cls.build_api().job(
                job_id=pk,
                application_id=application_id,
                application_spark_ui_url=application_spark_ui_url,
            ),
            user,
            **kwargs
        )
