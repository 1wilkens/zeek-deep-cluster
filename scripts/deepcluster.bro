module deepcluster;


# EVENT
global group_join_request: event(group: string, node_id: string, last_group_node: string);

global group_join_confirm: event(group: string);

global handover_request: event(group: string, node_ids: vector of string);

global handover_confirm: event(group: string, node_ids: vector of string);

# VARIABLES
global groups: set[string];

event deepcluster::group_join_request(group: string, node_id: string, last_group_node: string) {
    if (group in groups) {
        # singlehop XXX: publish only in "other direction"
        event group_join_request(group, node_id, "<own_id>");
    }
}


event deepcluster::group_join_confirm(group: string) {
    # XXX: possibly verify this?
    add groups[group];
}

event deepcluster::handover_request(group: string, node_ids: vector of string) {
}

event deepcluster::handover_confirm(group: string, node_ids: vector of string) {
}
