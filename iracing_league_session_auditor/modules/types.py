from .cron_matcher import CronMatcher

SessionBasicField = str | int | CronMatcher
SessionComplextField = dict[str, SessionBasicField]
SessionListField = list[SessionBasicField | SessionComplextField]
SessionTopLevelField = SessionBasicField | SessionComplextField | SessionListField
SessionDefinition = dict[str, SessionTopLevelField]
ExpectationDefinition = dict[str, str | SessionDefinition]
