from enum import Enum


class UserLevel(Enum):
    USER_UNKNOWN = -1
    USER_ADMINISTRATOR = 0
    USER_ELIGIBLE = 1
    USER_INELIGIBLE = 2
    USER_TEACHER = 3

UserLevelNames = {
    UserLevel.USER_ADMINISTRATOR: "Administrator",
    UserLevel.USER_ELIGIBLE: "Eligible",
    UserLevel.USER_INELIGIBLE: "Ineligible",
    UserLevel.USER_TEACHER: "Teacher",
    UserLevel.USER_UNKNOWN: "Unknown"
}
