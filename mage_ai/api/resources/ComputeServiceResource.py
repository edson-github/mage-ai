from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.data_preparation.models.project import Project
from mage_ai.services.compute.models import ComputeService


class ComputeServiceResource(GenericResource):
    @classmethod
    async def collection(cls, _query, _meta, user, **kwargs):
        resource = await cls.member(None, user, **kwargs)

        return cls.build_result_set(
            [
                resource.model,
            ],
            user,
            **kwargs
        )

    @classmethod
    def get_model(cls, _pk):
        return ComputeService.build(Project())

    @classmethod
    async def member(cls, pk, user, **kwargs):
        query_arg = kwargs.get('query', {})

        with_clusters = query_arg.get('with_clusters', [False])
        if with_clusters:
            with_clusters = with_clusters[0]

        compute_service = cls.get_model(pk)
        if with_clusters:
            compute_service.with_clusters = with_clusters

        return cls(compute_service, user, **kwargs)
