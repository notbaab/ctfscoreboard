from collections import namedtuple

AttackerFunctionTuple = namedtuple(
    'AttackerFunctionTuple',
    ['func', 'args', 'name', 'score', "service_check_func"]
)


def get_attack_config_list(attacker):
    config = [
        AttackerFunctionTuple(
            func=attacker.test_cmd_injection,
            args=(),
            name="cmd_injection",
            score=1,
            service_check_func=attacker.check_service,
        ),

        AttackerFunctionTuple(
            func=attacker.test_local_format_string,
            args=("chloe", "chloechloe"),
            name="local_format_string",
            score=1,
            service_check_func=attacker.check_service,
        ),

        AttackerFunctionTuple(
            func=attacker.test_buffer_overflow,
            args=(),
            name="buffer_overflow",
            score=1,
            service_check_func=attacker.check_service,
        ),

        AttackerFunctionTuple(
            func=attacker.test_ssh_jackbauer,
            args=(),
            name="ssh_jackbauer",
            score=1,
            service_check_func=attacker.check_service,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_surnow,
            args=(),
            name="ssh_surnow",
            score=1,
            service_check_func=attacker.check_service,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_chloe,
            args=(),
            name="ssh_chloe",
            score=1,
            service_check_func=attacker.check_service,
        ),
        AttackerFunctionTuple(
            func=attacker.test_backdoor_1,
            args=(),
            name="backdoor_1",
            score=1,
            service_check_func=attacker.check_service,
        ),
        AttackerFunctionTuple(
            func=attacker.test_lfi,
            args=(),
            name="lfi",
            score=1,
            service_check_func=attacker.check_service,
        ),
        AttackerFunctionTuple(
            func=attacker.test_reflected_xss,
            args=(),
            name="reflected_xss",
            score=1,
            service_check_func=attacker.check_service,
        ),
    ]
    return config
