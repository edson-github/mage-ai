from mage_ai.api.presenters.BasePresenter import BasePresenter


class DownloadPresenter(BasePresenter):
    default_attributes = [
        'uri',
    ]

    def present(self, **kwargs):
        return self.model if type(self.model) is dict else self.model.to_dict()
