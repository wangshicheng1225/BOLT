# coding=utf-8
# write entries to *.config file
import os
import sys
from config import *
from entries_generator_simple import DFAMatchEntriesSimpleGenerator
from entries_generator_shadow import NFAMatchEntriesShadowGenerator
# from entries_compress import compress_transition_sharing,shadow_code_transition_sharing
'''
- table_set_default <table name> <action name> <action parameters>
- table_add <table name> <action name> <match fields> => <action parameters> [priority]
- table_delete <table name> <entry handle>

- table_add t_ipv4_lpm a_ipv4_forward 10.0.0.10/32 => 00:04:00:00:00:00 1
- table_add t_ipv4_lpm a_ipv4_forward 10.0.1.10/32 => 00:04:00:00:00:01 2
'''




def writeRulesToConfig_from_mat_lst(ruleset, stride,table_id_list,filename=''):
    x = NFAMatchEntriesShadowGenerator(pattern_expression = ruleset, stride = stride, table_id_list=table_id_list)
    MAX_STRIDE = SWITCH_CONFIG['max_stride']
    root_state_ID = int(x.SC_ID_tuple[1][0],2)
    # print x.nfa_mat_entries

    # print x.nfa_shadow_mat_entries

    # print x.vstride_nfa_mat_entries
    # print "vstride_nfa_shadow_mat_entries"
    # print x.vstride_nfa_shadow_mat_entries
    # print "*********************************"
    policy_runtime_mat_entries = []
    # x.generate_runtime_mat_entries()
    runtime_nfa_shadow_mat_entries = x.get_runtime_nfa_shadow_mat_entries()
    runtime_policy_mat_entries = x.get_runtime_policy_mat_entries()
    runtime_mat_default_entries = x.get_runtime_mat_default_entries()
    
    max_priority = len(x.runtime_nfa_shadow_mat_entries) + 1
    cur_priority = max_priority
    entry_lst = []
    for entry_idx in runtime_nfa_shadow_mat_entries:
        # print entry_idx
        if entry_idx["table_name"][0:-1] == "t_DFA_match_":
            if entry_idx["action_name"][0:-1] == "a_set_state_":
                entry_str = 'table_add '+ entry_idx["table_name"] +' ' + entry_idx["action_name"] + ' '
                for idx in range(MAX_STRIDE):
                    field_name = SWITCH_CONFIG["received_char"] % idx
                    temp1 = str(entry_idx["match"][field_name][0])
                    temp2 = str(entry_idx["match"][field_name][1])
                    entry_str += temp1 + '&&&' + temp2 + ' '


                temp3 = str(entry_idx["match"]["meta.state"][0])
                temp4 = str(entry_idx["match"]["meta.state"][1])
                entry_str += temp3 + '&&&' + temp4 + ' => ' + str(entry_idx["action_params"]["_state"]) +' ' + str(entry_idx["action_params"]["modifier"]) + ' ' + str(cur_priority)
                cur_priority -=1
                print entry_str
                entry_lst.append(entry_str)
                # f.write("table_add", entry["table_name"], entry["action_name"], temp1+'&&&'+temp2,entry["match"]["meta.state"],"=>", entry["action_params"]["_state"], entry["action_params"]["modifier"])
                # print "table_add", entry["table_name"], entry["action_name"], temp1+'&&&'+temp2, temp3+'&&&'+temp4,"=>", entry["action_params"]["_state"], entry["action_params"]["modifier"],entry["priority"]
            # print "table_add", entry["table_name"], entry["action_name"], entry["match"]["hdr.patrns[0].string"],entry["match"]["meta.state"],"=>", entry["action_params"]["_state"], entry["action_params"]["modifier"]

    normal_priority = 1
    for entry_idx in runtime_policy_mat_entries:
        # print entry

        if entry_idx["table_name"] == "t_policy":
            entry_str = 'table_add ' + entry_idx["table_name"] +' ' + entry_idx["action_name"] + ' '
            temp1 = str(entry_idx["match"]["meta.pattern_state"][0])
            temp2 = str(entry_idx["match"]["meta.pattern_state"][1])
            entry_str += temp1+'&&&'+temp2 + ' => ' +  str(normal_priority)
            print entry_str
            entry_lst.append(entry_str)
            # print "table_add", entry_idx["table_name"], entry_idx["action_name"], temp1+'&&&'+temp2,"=>" , str(normal_priority)
                # f.write("table_add " + entry["table_name"] + ' '+ entry["action_name"] +' '+ entry["match"] + ' '+ "=>"+' '+entry["action_params"] )
    
    for entry_idx in runtime_mat_default_entries:
        # print entry
        if entry_idx["table_name"] == "t_get_stride":
            entry_str = 'table_set_default ' +  entry_idx["table_name"] + ' ' +entry_idx["action_name"] + ' ' + str(entry_idx["action_params"]["_stride"])
            
            # print "table_set_default", entry["table_name"], entry["action_name"], entry["action_params"]["_stride"]
        if entry_idx["table_name"] == "t_policy":
            entry_str = 'table_set_default ' +  entry_idx["table_name"] + ' ' +entry_idx["action_name"]
            
            # print "table_set_default", entry["table_name"], entry["action_name"]
            # print "table_set_default", entry["table_name"], entry["action_name"], entry["match"],"=>", entry["action_params"] 
        elif entry_idx["table_name"][0:-1] == "t_DFA_match_":
            entry_str = 'table_set_default ' +  entry_idx["table_name"] + ' ' +entry_idx["action_name"] + ' ' + str(entry_idx["action_params"]["_state"]) + ' ' + str(entry_idx["action_params"]["modifier"])
            
        print entry_str
        entry_lst.append(entry_str)
            #  print "table_set_default", entry["table_name"], entry["action_name"], entry["action_params"]["_state"], entry["action_params"]["modifier"]

    default_entry_lst = [ "table_set_default t_get_root_state a_get_root_state "+ str(root_state_ID), \
                        "table_add t_ipv4_lpm a_ipv4_forward 10.0.0.10/32 => 00:04:00:00:00:00 1",\
                        "table_add t_ipv4_lpm a_ipv4_forward 10.0.1.10/32 => 00:04:00:00:00:01 2"]
    
    for idx in default_entry_lst:
        entry_lst.append(idx)

    if filename == '':
        for idx in entry_lst:
            print idx
    else:
        with open(filename, 'w') as f:
            for idx in entry_lst:
                f.write(idx+'\n')


if __name__ == '__main__':

    ruleset = "she | he | her"
    writeRulesToConfig_from_mat_lst(ruleset,2,[0,1],filename='test.txt')