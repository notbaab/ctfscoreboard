from collections import namedtuple

AttackerFunctionTuple = namedtuple(
    'AttackerFunctionTuple',
    ['func', 'args', 'name', 'score', "service_check_func"]
)


def get_attack_config_list(attacker, sla_checker):
    config = [
        AttackerFunctionTuple(
            func=attacker.test_cmd_injection,
            args=(),
            name="Command Injection",
            score=1,
            service_check_func=sla_checker.check_cmd_injection,
        ),
        AttackerFunctionTuple(
            func=attacker.test_local_format_string_chloe,
            args=(),
            name="Local Format String",
            score=1,
            service_check_func=sla_checker.check_local_format_string,
        ),

        AttackerFunctionTuple(
            func=attacker.test_buffer_overflow,
            args=(),
            name="Buffer Overflow",
            score=1,
            service_check_func=sla_checker.check_buffer_overflow,
        ),

        AttackerFunctionTuple(
            func=attacker.test_ssh_jackbauer,
            args=(),
            name="ssh_jackbauer",
            score=1,
            service_check_func=sla_checker.check_ssh,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_surnow,
            args=(),
            name="ssh_surnow",
            score=1,
            service_check_func=sla_checker.check_ssh,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_chloe,
            args=(),
            name="ssh_chloe",
            score=1,
            service_check_func=sla_checker.check_ssh,
        ),
        AttackerFunctionTuple(
            func=attacker.test_backdoor_1,
            args=(),
            name="backdoor",
            score=1,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_lfi,
            args=(),
            name="lfi",
            score=1,
            service_check_func=sla_checker.check_lfi,
        ),
        AttackerFunctionTuple(
            func=attacker.test_reflected_xss,
            args=(),
            name="reflected xss",
            score=1,
            service_check_func=sla_checker.check_reflected_xss,
        ),
        AttackerFunctionTuple(
            func=attacker.test_arbitrary_file_upload,
            args=(),
            name="arbitrary file upload",
            score=1,
            service_check_func=sla_checker.check_arbitrary_file_upload,
        ),
        AttackerFunctionTuple(
            func=attacker.test_dom_based_xss,
            args=(),
            name="dom based xss",
            score=1,
            service_check_func=sla_checker.check_dom_based_xss,
        ),
    ]
    return config
