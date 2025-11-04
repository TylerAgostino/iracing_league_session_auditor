from enum import Enum
from typing import TypedDict, Union
from .cron_matcher import CronMatcher
from collections.abc import Mapping as mapping


class ComparisonOperator(Enum):
    EQUALS = "="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    NOT_EQUALS = "!="


class ComparisonValue(TypedDict):
    value: Union[str, int]
    operator: ComparisonOperator


SessionBasicField = str | int | CronMatcher | ComparisonValue
SessionComplextField = mapping[str, SessionBasicField]
SessionListField = list[SessionBasicField | SessionComplextField]
SessionTopLevelField = SessionBasicField | SessionComplextField | SessionListField
SessionDefinition = mapping[str, SessionTopLevelField]
ExpectationDefinition = mapping[str, str | SessionDefinition]
