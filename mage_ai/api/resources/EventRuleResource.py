from mage_ai.api.resources.GenericResource import GenericResource
from mage_ai.orchestration.db import safe_db_query


class EventRuleResource(GenericResource):
    @classmethod
    @safe_db_query
    def member(cls, pk, user, **kwargs):
        rules = []

        if pk == 'aws':
            from mage_ai.services.aws.events.events import get_all_event_rules

            try:
                rules = get_all_event_rules()
            except Exception as err:
                print(f'[WARNING] EventRuleResource.member: {err}')

        return cls(dict(rules=rules), user, **kwargs)
