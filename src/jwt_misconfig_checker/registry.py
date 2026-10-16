from jwt_misconfig_checker.checks.alg_none import AlgNoneCheck
from jwt_misconfig_checker.checks.header_params import HeaderParametersCheck
from jwt_misconfig_checker.checks.header_typ import HeaderTypCheck
from jwt_misconfig_checker.checks.weak_alg import WeakAlgorithmCheck
from jwt_misconfig_checker.models import Check

DEFAULT_CHECKS: tuple[Check, ...] = (
    AlgNoneCheck(),
    WeakAlgorithmCheck(),
    HeaderParametersCheck(),
    HeaderTypCheck(),
)