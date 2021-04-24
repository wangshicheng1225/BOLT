# coding=utf-8

SWITCH_CONFIG = {
    "stride_mat_name": "t_get_stride",
    "dfa_mat_name": "t_DFA_match_%d",
    "policy_mat_name": "t_policy",
    "received_char": "hdr.patrns[%d].string",
    "current_state": "meta.state",
    "pattern_state": "meta.pattern_state",
    "accept_action_name": "a_accept",
    "goto_action_name": "a_set_state_%d",
    "stride_action_name": "a_get_stride",
    "policy_action_name": "a_set_lpm",
    "drop_action_name": "a_drop",
    "stride_param": "_stride",
    "next_state": "_state",
    "modifier": "modifier",
    "max_stride": 2,
}

# TOFINO_CONFIG = {
#     "stride_mat_name": "t_get_stride",
#     "dfa_mat_name": "t_DFA_match_%d",
#     "policy_mat_name": "t_policy",
#     "received_char": "idsMeta.w%d",
#     "current_state": "idsMeta.state",
#     "pattern_state": "idsMeta.pattern_state",
#     "accept_action_name": "a_accept",
#     "goto_action_name": "a_set_state_%d",
#     "stride_action_name": "a_get_stride",
#     "policy_action_name": "a_set_lpm",
#     "drop_action_name": "a_drop",
#     "stride_param": "_stride",
#     "next_state": "_state",
#     "modifier": "modifier",
# }

PATTERN_MAX_NUM = 16
