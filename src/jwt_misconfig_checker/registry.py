from jwt_misconfig_checker.checks.alg_none import AlgNoneCheck
from jwt_misconfig_checker.checks.header_params import HeaderParametersCheck
from jwt_misconfig_checker.checks.header_typ import HeaderTypCheck
from jwt_misconfig_checker.checks.identity_claims import IdentityClaimsCheck
from jwt_misconfig_checker.checks.kid_injection import KidInjectionCheck
from jwt_misconfig_checker.checks.sensitive_data import SensitiveDataCheck
from jwt_misconfig_checker.checks.time_claims import TimeClaimsCheck
from jwt_misconfig_checker.checks.weak_alg import WeakAlgorithmCheck
from jwt_misconfig_checker.models import Check

DEFAULT_CHECKS: tuple[Check, ...] = (
    AlgNoneCheck(),
    WeakAlgorithmCheck(),
    HeaderParametersCheck(),
    KidInjectionCheck(),
    HeaderTypCheck(),
    TimeClaimsCheck(),
    IdentityClaimsCheck(),
    SensitiveDataCheck(),
)
