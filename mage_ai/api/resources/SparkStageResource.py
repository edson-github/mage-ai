from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.api.resources.mixins.spark import SparkApplicationChild
from mage_ai.services.spark.models.stages import Stage


class SparkStageResource(GenericResource, SparkApplicationChild):
    @classmethod
    async def collection(cls, query_arg, _meta, user, **kwargs):
        query = {}

        details = query_arg.get('details', [False])
        if details:
            details = details[0]
        if details:
            query['details'] = details

        return cls.build_result_set(
            await cls.build_api().stages(query=query), user, **kwargs
        )

    @classmethod
    async def get_model(cls, pk) -> Stage:
        return Stage.load(stage_id=pk)

    @classmethod
    async def member(cls, pk, user, **kwargs):
        query_arg = kwargs.get('query', {})

        query = {}
        quantiles = query_arg.get('quantiles', [None])
        if quantiles:
            quantiles = quantiles[0]
        if quantiles:
            query['quantiles'] = quantiles

        if with_summaries := query_arg.get('withSummaries', [False]):
            with_summaries = with_summaries[0]
            if quantiles:
                query['withSummaries'] = with_summaries

        application_id = cls.application_calculated_id_from_query(query_arg)

        application_spark_ui_url = query_arg.get('application_spark_ui_url', [])
        if application_spark_ui_url:
            application_spark_ui_url = application_spark_ui_url[0]

        stage = await cls.build_api().stage(
            application_id=application_id,
            application_spark_ui_url=application_spark_ui_url,
            stage_id=pk,
            query=query if query else None,
        )

        return cls(stage, user, **kwargs)
