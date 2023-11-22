from dataclasses import fields

from mage_ai.api.presenters.BasePresenter import BasePresenter
from mage_ai.cluster_manager.config import (
    CloudRunWorkspaceConfig,
    EcsWorkspaceConfig,
    KubernetesWorkspaceConfig,
)
from mage_ai.shared.hash import merge_dict


class WorkspacePresenter(BasePresenter):
    default_attributes = list(
        set(
            [
                'access',
                'cluster_type',
                'instance',
                'name',
                'repo_path',
                'success',
                *[f.name for f in fields(KubernetesWorkspaceConfig)],
                *[f.name for f in fields(CloudRunWorkspaceConfig)],
                *[f.name for f in fields(EcsWorkspaceConfig)],
            ]
        )
    )

    async def present(self, **kwargs):
        if workspace := self.model.pop('workspace', None):
            workspace_config = workspace.to_dict()
        else:
            workspace_config = dict()
        return merge_dict(workspace_config, self.model)
