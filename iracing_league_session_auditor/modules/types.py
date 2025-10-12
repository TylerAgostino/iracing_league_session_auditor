from .cron_matcher import CronMatcher
from collections.abc import Mapping as mapping

SessionBasicField = str | int | CronMatcher
SessionComplextField = mapping[str, SessionBasicField]
SessionListField = list[SessionBasicField | SessionComplextField]
SessionTopLevelField = SessionBasicField | SessionComplextField | SessionListField
SessionDefinition = mapping[str, SessionTopLevelField]
ExpectationDefinition = mapping[str, str | SessionDefinition]
