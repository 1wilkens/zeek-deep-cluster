@load base/frameworks/broker

module DeepCluster;

export {
    ## Record type to indicate a node in a cluster.
    type Node: record {
        ## The IP address of the cluster node.
        ip:           addr;
        ## If the *ip* field is a non-global IPv6 address, this field
        ## can specify a particular :rfc:`4007` ``zone_id``.
        zone_id:      string      &default="";
        ## The port that this node will listen on for peer connections.
        p:            port;
        ## Identifier for the interface a worker is sniffing.
        interface:    string      &optional;
        ## Name of the manager node this node uses.  For workers and proxies.
        manager:      string      &optional;
        ## Name of a time machine node with which this node connects.
        time_machine: string      &optional;
        ## A unique identifier assigned to the node by the broker framework.
        ## This field is only set while a node is connected.
        id: string                &optional;
    };

    ## DeepCluster layout definition.  This should be placed into a filter
    ## named cluster-layout.bro somewhere in the BROPATH.  It will be
    ## automatically loaded if the CLUSTER_NODE environment variable is set.
    ## Note that BroControl handles all of this automatically.
    ## The table is typically indexed by node names/labels (e.g. "manager"
    ## or "worker-1").
    const nodes: table[string] of Node = {} &redef;

    const node_name = getenv("NODE_NAME") &redef;
}

# EVENT
global group_join_request: event(group: string, node_id: string, last_group_node: string);

global group_join_confirm: event(group: string);

global handover_request: event(group: string, node_ids: vector of string);

global handover_confirm: event(group: string, node_ids: vector of string);

# VARIABLES
global groups: set[string];

event bro_init() &priority=5 {
    # Validate our node_name against the given config
    if (node_name != "" && node_name !in nodes) {
        Reporter::error(fmt("'%s' is not a valid node in the Deepcluster::nodes configuration", node_name));
        terminate();
    }

    # Set our own id in the Node
    nodes[node_name]$id = Broker::node_id();
}

event Deepcluster::group_join_request(group: string, node_id: string, last_group_node: string) {
    local self = nodes[node_name];

    if (group in groups) {
        # singlehop XXX: publish only in "other direction"
        event group_join_request(group, node_id, self$id);
    }
}


event Deepcluster::group_join_confirm(group: string) {
    # XXX: possibly verify this?
    add groups[group];
}

event Deepcluster::handover_request(group: string, node_ids: vector of string) {
}

event Deepcluster::handover_confirm(group: string, node_ids: vector of string) {
}

