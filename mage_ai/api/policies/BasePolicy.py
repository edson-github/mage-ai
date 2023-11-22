import importlib
import inspect
from collections.abc import Iterable
from typing import Callable, List, Tuple, Union

import inflection

from mage_ai import settings
from mage_ai.api.constants import AttributeOperationType, AttributeType
from mage_ai.api.errors import ApiError
from mage_ai.api.mixins.result_set import ResultSetMixIn
from mage_ai.api.oauth_scope import OauthScope
from mage_ai.api.operations.constants import OperationType
from mage_ai.api.policies.mixins.user_permissions import UserPermissionMixIn
from mage_ai.api.result_set import ResultSet
from mage_ai.api.utils import (
    has_at_least_admin_role,
    has_at_least_editor_role,
    has_at_least_editor_role_and_notebook_edit_access,
    has_at_least_editor_role_and_pipeline_edit_access,
    has_at_least_viewer_role,
    is_owner,
)
from mage_ai.data_preparation.repo_manager import get_project_uuid
from mage_ai.orchestration.constants import Entity
from mage_ai.server.api.constants import URL_PARAMETER_API_KEY
from mage_ai.services.tracking.metrics import increment
from mage_ai.settings import (
    DISABLE_NOTEBOOK_EDIT_ACCESS,
    REQUIRE_USER_AUTHENTICATION,
    REQUIRE_USER_PERMISSIONS,
)
from mage_ai.shared.hash import extract, ignore_keys

CONTEXT_DATA_KEY_USER_ROLE_VALIDATIONS = '__user_role_validations'


class BasePolicy(UserPermissionMixIn, ResultSetMixIn):
    action_rules = {}
    query_rules = {}
    read_rules = {}
    write_rules = {}
    override_permission_action_rules = {}
    override_permission_query_rules = {}
    override_permission_read_rules = {}
    override_permission_write_rules = {}

    def __init__(self, resource, current_user, **kwargs):
        self.current_user = current_user
        self.options = kwargs
        self.resource = resource
        self.parent_model_attr = None
        self.parent_resource_attr = None
        self.result_set_attr = None

        if resource:
            self.resources = resource if isinstance(resource, Iterable) else [resource]
        else:
            self.result_set_attr = ResultSet([])

        # This is only used to override the environment variable when bootstrapping permissions.
        self.disable_notebook_edit_access_override = None

    @property
    def entity(self) -> Tuple[Union[Entity, None], Union[str, None]]:
        return Entity.PROJECT, get_project_uuid()

    @classmethod
    def action_rule(cls, action):
        if REQUIRE_USER_PERMISSIONS:
            return cls.action_rule_with_permissions(action)

        if not cls.action_rules.get(cls.__name__):
            cls.action_rules[cls.__name__] = {}
        return cls.action_rules[cls.__name__].get(action)

    @classmethod
    def override_permission_action_rule(cls, action):
        if not cls.override_permission_action_rules.get(cls.__name__):
            cls.override_permission_action_rules[cls.__name__] = {}
        return cls.override_permission_action_rules[cls.__name__].get(action)

    @classmethod
    def query_rule(cls, query):
        if REQUIRE_USER_PERMISSIONS:
            return cls.attribute_rule_with_permissions(AttributeOperationType.QUERY, query)

        if not cls.query_rules.get(cls.__name__):
            cls.query_rules[cls.__name__] = {}
        return cls.query_rules[cls.__name__].get(query)

    @classmethod
    def override_permission_query_rule(cls, query):
        if not cls.override_permission_query_rules.get(cls.__name__):
            cls.override_permission_query_rules[cls.__name__] = {}
        return cls.override_permission_query_rules[cls.__name__].get(query)

    @classmethod
    def read_rule(cls, read):
        if REQUIRE_USER_PERMISSIONS:
            return cls.attribute_rule_with_permissions(AttributeOperationType.READ, read)

        if not cls.read_rules.get(cls.__name__):
            cls.read_rules[cls.__name__] = {}
        return cls.read_rules[cls.__name__].get(read)

    @classmethod
    def override_permission_read_rule(cls, read):
        if not cls.override_permission_read_rules.get(cls.__name__):
            cls.override_permission_read_rules[cls.__name__] = {}
        return cls.override_permission_read_rules[cls.__name__].get(read)

    @classmethod
    def write_rule(cls, write):
        if REQUIRE_USER_PERMISSIONS:
            return cls.attribute_rule_with_permissions(AttributeOperationType.WRITE, write)

        if not cls.write_rules.get(cls.__name__):
            cls.write_rules[cls.__name__] = {}
        return cls.write_rules[cls.__name__].get(write)

    @classmethod
    def override_permission_write_rule(cls, write):
        if not cls.override_permission_write_rules.get(cls.__name__):
            cls.override_permission_write_rules[cls.__name__] = {}
        return cls.override_permission_write_rules[cls.__name__].get(write)

    @classmethod
    def allow_actions(cls, array, **kwargs):
        if not cls.action_rules.get(cls.__name__):
            cls.action_rules[cls.__name__] = {}
        if not cls.override_permission_action_rules.get(cls.__name__):
            cls.override_permission_action_rules[cls.__name__] = {}

        array_use = array or [OperationType.ALL]
        for key in array_use:
            if not cls.action_rules[cls.__name__].get(key):
                cls.action_rules[cls.__name__][key] = {}
            for scope in kwargs.get('scopes', []):
                if scope not in cls.action_rules[cls.__name__][key]:
                    cls.action_rules[cls.__name__][key][scope] = []
                cls.action_rules[cls.__name__][key][scope].append(
                    extract(kwargs, ['condition'])
                )

            if not cls.override_permission_action_rules[cls.__name__].get(key):
                cls.override_permission_action_rules[cls.__name__][key] = {}
            for scope in kwargs.get('scopes', []):
                if (
                    scope
                    not in cls.override_permission_action_rules[cls.__name__][key]
                ):
                    cls.override_permission_action_rules[cls.__name__][key][scope] = []
                cls.override_permission_action_rules[cls.__name__][key][
                    scope
                ].append(
                    extract(
                        kwargs,
                        [
                            'override_permission_condition',
                        ],
                    )
                )

    @classmethod
    def allow_query(cls, array: List = None, **kwargs):
        if not cls.query_rules.get(cls.__name__):
            cls.query_rules[cls.__name__] = {}
        if not cls.override_permission_query_rules.get(cls.__name__):
            cls.override_permission_query_rules[cls.__name__] = {}

        array_use = array or [AttributeType.ALL]
        for key in array_use:
            if not cls.query_rules[cls.__name__].get(key):
                cls.query_rules[cls.__name__][key] = {}
            if not cls.override_permission_query_rules[cls.__name__].get(key):
                cls.override_permission_query_rules[cls.__name__][key] = {}

            actions = kwargs.get('on_action', [OperationType.ALL])
            actions = actions if isinstance(actions, list) else [actions]

            for scope in kwargs.get('scopes', []):
                if not cls.query_rules[cls.__name__][key].get(scope):
                    cls.query_rules[cls.__name__][key][scope] = {}
                for action in actions:
                    if action not in cls.query_rules[cls.__name__][key][scope]:
                        cls.query_rules[cls.__name__][key][scope][action] = []
                    cls.query_rules[cls.__name__][key][scope][action].append(
                        extract(
                            kwargs,
                            [
                                'condition',
                            ],
                        )
                    )

                if not cls.override_permission_query_rules[cls.__name__][key].get(
                    scope
                ):
                    cls.override_permission_query_rules[cls.__name__][key][scope] = {}
                for action in actions:
                    if (
                        action
                        not in cls.override_permission_query_rules[cls.__name__][
                            key
                        ][scope]
                    ):

                        cls.override_permission_query_rules[cls.__name__][key][scope][action] = []
                    cls.override_permission_query_rules[cls.__name__][key][scope][
                        action
                    ].append(extract(kwargs, ['override_permission_condition']))

    @classmethod
    def allow_read(cls, array, **kwargs):
        if not cls.read_rules.get(cls.__name__):
            cls.read_rules[cls.__name__] = {}
        if not cls.override_permission_read_rules.get(cls.__name__):
            cls.override_permission_read_rules[cls.__name__] = {}

        for key in array:
            if not cls.read_rules[cls.__name__].get(key):
                cls.read_rules[cls.__name__][key] = {}
            if not cls.override_permission_read_rules[cls.__name__].get(key):
                cls.override_permission_read_rules[cls.__name__][key] = {}

            actions = kwargs.get('on_action', [OperationType.ALL])
            actions = actions if isinstance(actions, list) else [actions]

            for scope in kwargs.get('scopes', []):
                if not cls.read_rules[cls.__name__][key].get(scope):
                    cls.read_rules[cls.__name__][key][scope] = {}
                for action in actions:
                    if action not in cls.read_rules[cls.__name__][key][scope]:
                        cls.read_rules[cls.__name__][key][scope][action] = []
                    cls.read_rules[cls.__name__][key][scope][action].append(
                        extract(kwargs, ['condition'])
                    )

                if not cls.override_permission_read_rules[cls.__name__][key].get(
                    scope
                ):
                    cls.override_permission_read_rules[cls.__name__][key][scope] = {}
                for action in actions:
                    if (
                        action
                        not in cls.override_permission_read_rules[cls.__name__][
                            key
                        ][scope]
                    ):
                        cls.override_permission_read_rules[cls.__name__][key][scope][action] = []
                    cls.override_permission_read_rules[cls.__name__][key][scope][
                        action
                    ].append(extract(kwargs, ['override_permission_condition']))

    @classmethod
    def allow_write(cls, array, **kwargs):
        if not cls.write_rules.get(cls.__name__):
            cls.write_rules[cls.__name__] = {}
        if not cls.override_permission_write_rules.get(cls.__name__):
            cls.override_permission_write_rules[cls.__name__] = {}

        for key in array:
            if not cls.write_rules[cls.__name__].get(key):
                cls.write_rules[cls.__name__][key] = {}
            if not cls.override_permission_write_rules[cls.__name__].get(key):
                cls.override_permission_write_rules[cls.__name__][key] = {}

            actions = kwargs.get('on_action', [OperationType.ALL])
            actions = actions if isinstance(actions, list) else [actions]

            for scope in kwargs.get('scopes', []):
                if not cls.write_rules[cls.__name__][key].get(scope):
                    cls.write_rules[cls.__name__][key][scope] = {}
                for action in actions:
                    if action not in cls.write_rules[cls.__name__][key][scope]:
                        cls.write_rules[cls.__name__][key][scope][action] = []
                    cls.write_rules[cls.__name__][key][scope][action].append(
                        extract(kwargs, ['condition'])
                    )

                if not cls.override_permission_write_rules[cls.__name__][key].get(
                    scope
                ):
                    cls.override_permission_write_rules[cls.__name__][key][scope] = {}
                for action in actions:
                    if (
                        action
                        not in cls.override_permission_write_rules[cls.__name__][
                            key
                        ][scope]
                    ):

                        cls.override_permission_write_rules[cls.__name__][key][scope][action] = []
                    cls.override_permission_write_rules[cls.__name__][key][scope][
                        action
                    ].append(extract(kwargs, ['override_permission_condition']))

    @classmethod
    def resource_name(cls):
        return inflection.pluralize(cls.resource_name_singular())

    @classmethod
    def model_name(cls) -> str:
        return cls.__name__.replace('Policy', '')

    @classmethod
    def resource_name_singular(cls):
        return inflection.underscore(cls.__name__.replace('Policy', '')).lower()

    def is_owner(self) -> bool:
        def _validate(
            user=self.current_user,
            entity=self.entity[0],
            entity_id=self.entity[1],
        ):
            return is_owner(
                user,
                entity=entity,
                entity_id=entity_id,
            )

        return self.__get_and_set_user_role_validation('is_owner', _validate)

    def has_at_least_admin_role(self) -> bool:
        def _validate(
            user=self.current_user,
            entity=self.entity[0],
            entity_id=self.entity[1],
        ):
            return has_at_least_admin_role(
                user,
                entity=entity,
                entity_id=entity_id,
            )

        return self.__get_and_set_user_role_validation('has_at_least_admin_role', _validate)

    def has_at_least_editor_role(self) -> bool:
        def _validate(
            user=self.current_user,
            entity=self.entity[0],
            entity_id=self.entity[1],
        ):
            return has_at_least_editor_role(
                user,
                entity=entity,
                entity_id=entity_id,
            )

        return self.__get_and_set_user_role_validation('has_at_least_editor_role', _validate)

    def has_at_least_editor_role_and_notebook_edit_access(
        self,
        disable_notebook_edit_access_override: int = None,
    ) -> bool:
        disable_notebook = (
            disable_notebook_edit_access_override or
            self.disable_notebook_edit_access_override
        )

        def _validate(
            user=self.current_user,
            entity=self.entity[0],
            entity_id=self.entity[1],
            disable_notebook=disable_notebook,
        ):
            return has_at_least_editor_role_and_notebook_edit_access(
                user,
                entity=entity,
                entity_id=entity_id,
                disable_notebook_edit_access_override=disable_notebook,
            )

        return self.__get_and_set_user_role_validation(
            'has_at_least_editor_role_and_notebook_edit_access',
            _validate,
        )

    def has_at_least_editor_role_and_pipeline_edit_access(
        self,
        disable_notebook_edit_access_override: int = None,
    ) -> bool:
        disable_notebook = (
            disable_notebook_edit_access_override or
            self.disable_notebook_edit_access_override
        )

        def _validate(
            user=self.current_user,
            entity=self.entity[0],
            entity_id=self.entity[1],
            disable_notebook=disable_notebook,
        ):
            return has_at_least_editor_role_and_pipeline_edit_access(
                user,
                entity=entity,
                entity_id=entity_id,
                disable_notebook_edit_access_override=disable_notebook,
            )

        return self.__get_and_set_user_role_validation(
            'has_at_least_editor_role_and_pipeline_edit_access',
            _validate,
        )

    def has_at_least_viewer_role(self) -> bool:
        def _validate(
            user=self.current_user,
            entity=self.entity[0],
            entity_id=self.entity[1],
        ):
            return has_at_least_viewer_role(
                user,
                entity=entity,
                entity_id=entity_id,
            )

        return self.__get_and_set_user_role_validation('has_at_least_viewer_role', _validate)

    async def authorize_action(self, action):
        if (
            not REQUIRE_USER_AUTHENTICATION and
            not DISABLE_NOTEBOOK_EDIT_ACCESS and
            action in [OperationType.CREATE, OperationType.DELETE, OperationType.UPDATE]
        ):
            return True

        if not DISABLE_NOTEBOOK_EDIT_ACCESS and REQUIRE_USER_PERMISSIONS and self.is_owner():
            return True

        if config := self.__class__.action_rule(action):
            await self.__validate_scopes(action, config.keys())

            rules = config.get(self.current_scope()) or []
            if conditions := [
                rule.get('condition') for rule in rules if rule.get('condition')
            ]:
                override_permission_conditions = None
                if config_override := self.__class__.override_permission_action_rule(
                    action
                ):
                    if override_rules := config_override.get(self.current_scope()):
                        override_permission_conditions = \
                                [rule.get('override_permission_condition') for rule in override_rules
                                if rule.get('override_permission_condition')]

                await self.__validate_condition(
                    action,
                    conditions,
                    operation=action,
                    override_permission_conditions=override_permission_conditions
                )
        else:
            error = ApiError.UNAUTHORIZED_ACCESS
            error.update(
                {
                    'message': f'The {action} action is disabled for {self.resource_name()}.'
                }
            )
            raise ApiError(error)

    async def authorize_attribute(self, read_or_write, attrb, **kwargs):
        if not REQUIRE_USER_AUTHENTICATION or self.is_owner():
            return True

        if not DISABLE_NOTEBOOK_EDIT_ACCESS and REQUIRE_USER_PERMISSIONS and self.is_owner():
            return True

        api_operation_action = self.options.get(
            'api_operation_action',
            kwargs.get('api_operation_action', OperationType.ALL),
        )

        attribute_operation = None
        if read_or_write == 'read':
            attribute_operation = AttributeOperationType.READ
            orig_config = self.__class__.read_rule(attrb)
            orig_config_override = self.__class__.override_permission_read_rule(attrb)
        else:
            attribute_operation = AttributeOperationType.WRITE
            orig_config = self.__class__.write_rule(attrb)
            orig_config_override = self.__class__.override_permission_write_rule(attrb)

        rules = None
        if orig_config:
            await self.__validate_scopes(attrb, orig_config.keys())
            config_scope = orig_config.get(self.current_scope(), {})
            rules = config_scope.get(api_operation_action) or None

            if rules is None:
                rules = config_scope.get(OperationType.ALL)

        override_permission_conditions = None
        if orig_config_override:
            await self.__validate_scopes(attrb, orig_config_override.keys())
            config_override_scope = orig_config_override.get(self.current_scope(), {})
            if override_rules := config_override_scope.get(
                api_operation_action
            ) or config_override_scope.get(OperationType.ALL):
                override_permission_conditions = \
                        [rule.get('override_permission_condition') for rule in override_rules
                        if rule.get('override_permission_condition')]

        if rules is None:
            error = ApiError.UNAUTHORIZED_ACCESS
            error.update(
                {
                    'message': f'{read_or_write} of {attrb} on {api_operation_action} is disabled for {self.__class__.resource_name()}.'
                }
            )
            raise ApiError(error)

        if conditions := [
            rule.get('condition') for rule in rules if rule.get('condition')
        ]:
            await self.__validate_condition(
                attrb,
                conditions,
                attribute_operation=attribute_operation,
                operation=api_operation_action,
                override_permission_conditions=override_permission_conditions,
                **kwargs,
            )

    async def authorize_attributes(self, read_or_write, attrbs, **kwargs):
        if not REQUIRE_USER_AUTHENTICATION or self.is_owner():
            return True

        for attrb in attrbs:
            await self.authorize_attribute(read_or_write, attrb, **kwargs)

    async def authorize_query(self, query, **kwargs):
        # If DISABLE_NOTEBOOK_EDIT_ACCESS is enabled, we will need to perform
        # the policy check for queries.
        if not DISABLE_NOTEBOOK_EDIT_ACCESS and (
            not REQUIRE_USER_AUTHENTICATION or self.is_owner()
        ):
            return True

        if not DISABLE_NOTEBOOK_EDIT_ACCESS and REQUIRE_USER_PERMISSIONS and self.is_owner():
            return True

        query_filtered = ignore_keys(query or {}, [URL_PARAMETER_API_KEY])

        if not query_filtered:
            return True

        api_operation_action = self.options.get(
            'api_operation_action',
            kwargs.get('api_operation_action', OperationType.ALL),
        )

        for key, value in query_filtered.items():
            if key == settings.QUERY_API_KEY:
                continue

            error_message = f'Query parameter {key} of value {value} ' \
                    f'is not permitted on {api_operation_action} operation ' \
                    f'for {self.__class__.resource_name()}.'

            orig_config = self.__class__.query_rule(key) or \
                    self.__class__.query_rule(AttributeType.ALL)

            rules = None
            if orig_config:
                await self.__validate_scopes(key, orig_config.keys())
                config_scope = orig_config.get(self.current_scope(), {})
                rules = config_scope.get(api_operation_action) or None

                if rules is None:
                    rules = config_scope.get(OperationType.ALL)

            orig_config_override = self.__class__.override_permission_query_rule(key) or \
                    self.__class__.override_permission_query_rule(AttributeType.ALL)

            override_permission_conditions = None
            if orig_config_override:
                await self.__validate_scopes(key, orig_config_override.keys())
                config_override_scope = orig_config_override.get(self.current_scope(), {})
                if override_rules := config_override_scope.get(
                    api_operation_action
                ) or config_override_scope.get(OperationType.ALL):
                    override_permission_conditions = \
                            [rule.get('override_permission_condition') for rule in override_rules
                            if rule.get('override_permission_condition')]

            if rules is None:
                error = ApiError.UNAUTHORIZED_ACCESS
                error.update({
                    'message': error_message,
                })
                raise ApiError(error)

            if conditions := [
                rule.get('condition') for rule in rules if rule.get('condition')
            ]:
                await self.__validate_condition(
                    key,
                    conditions,
                    message=error_message,
                    operation=api_operation_action,
                    override_permission_conditions=override_permission_conditions,
                )

    def parent_model(self):
        if not self.parent_model_attr:
            self.parent_model_attr = self.options.get('parent_model', None)
        return self.parent_model_attr

    def parent_resource(self):
        if not self.parent_resource_attr and self.parent_model():
            parent_model_class = inflection.singularize(
                self.parent_model().__class__.__name__,
            )
            self.parent_resource_attr = getattr(
                importlib.import_module(
                    f'mage_ai.api.resources.{parent_model_class}Resource'
                ),
                f'{parent_model_class}Resource',
            )(self.parent_model(), self.current_user, **self.options)
        return self.parent_resource_attr

    def current_scope(self) -> OauthScope:
        # If edit access is disabled and user authentication is not enabled, we want to
        # treat the user as if they are logged in, so we can stop users from accessing
        # certain endpoints.
        if self.current_user or \
                (DISABLE_NOTEBOOK_EDIT_ACCESS and not REQUIRE_USER_AUTHENTICATION):
            return OauthScope.CLIENT_PRIVATE
        else:
            return OauthScope.CLIENT_PUBLIC

    def result_set(self) -> ResultSet:
        return self.resource.result_set() if self.resource else self.result_set_attr

    async def __validate_condition(
        self,
        action,
        conditions_functions: List[Callable[['BasePolicy'], None]],
        attribute_operation: AttributeOperationType = None,
        operation: OperationType = None,
        override_permission_conditions: List[Callable[['BasePolicy'], None]] = None,
        **kwargs,
    ):
        if not conditions_functions:
            return

        validation = False
        for condition in conditions_functions:
            validation = condition(self)
            if validation is not None and inspect.isawaitable(validation):
                validation = await validation

            if validation:
                break

        if not validation and override_permission_conditions:
            for condition in override_permission_conditions:
                validation = condition(self)
                if validation is not None and inspect.isawaitable(validation):
                    validation = await validation

                if validation:
                    break

        if not validation:
            r_name = self.resource_name()
            error = ApiError.UNAUTHORIZED_ACCESS
            message = f'Unauthorized access for {action} on {r_name}'

            if attribute_operation:
                message = f'Unauthorized {attribute_operation} access for {action} on {r_name}'
                if operation:
                    message = f'{message} for {operation} operation'
            elif operation:
                message = f'Unauthorized operation {operation} on {r_name}'

            error.update({
                'message': kwargs.get(
                    'message',
                    f'{message}, failed condition.',
                ),
            })
            increment(
                'api_error.unauthorized_access',
                tags={
                    'action': action,
                    'attribute_operation': attribute_operation,
                    'policy_class_name': self.__class__.__name__,
                    'id': self.resource.id if hasattr(
                        self.resource,
                        'id') else None,
                    'operation': operation,
                })
            if settings.DEBUG:
                error['debug'] = {
                    'action': action,
                    'attribute_operation': attribute_operation,
                    'operation': operation,
                }
            raise ApiError(error)

    async def __validate_scopes(self, val, scopes):
        error = ApiError.UNAUTHORIZED_ACCESS
        if not REQUIRE_USER_AUTHENTICATION:
            return
        if OauthScope.CLIENT_ALL in scopes:
            return
        elif not self.current_user and OauthScope.CLIENT_PUBLIC not in scopes:
            error.update({'message': f'Private access for {val} only, invalid scope.'})
            if settings.DEBUG:
                error['debug'] = {
                    'class': self.__class__.__name__,
                    'scopes': scopes,
                }
            raise ApiError(error)
        elif self.current_user and OauthScope.CLIENT_PRIVATE not in scopes:
            error.update({'message': f'Public access for {val} only, invalid scope.'})
            if settings.DEBUG:
                error['debug'] = {
                    'scopes': scopes,
                }
            raise ApiError(error)

    def __get_and_set_user_role_validation(
        self,
        key: str,
        condition: Callable,
    ) -> bool:
        mapping = self.result_set().context.data.get(CONTEXT_DATA_KEY_USER_ROLE_VALIDATIONS) or {}
        if key in mapping:
            return mapping.get(key)

        if CONTEXT_DATA_KEY_USER_ROLE_VALIDATIONS not in self.result_set().context.data:
            self.result_set().context.data[CONTEXT_DATA_KEY_USER_ROLE_VALIDATIONS] = {}

        validation = condition()
        self.result_set().context.data[CONTEXT_DATA_KEY_USER_ROLE_VALIDATIONS][key] = validation

        return validation
