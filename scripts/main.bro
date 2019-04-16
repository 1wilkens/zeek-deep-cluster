@load base/frameworks/broker

module DeepCluster;

const DEBUG = T;

export {

    # Enable broker event forwarding
    redef Broker::forward_messages = T;

    const topic_prefix = "bro/deepcluster/" &redef;

    const node_topic_prefix = topic_prefix + "node/" &redef;
    const group_topic_prefix = topic_prefix + "group/" &redef;
    const control_topic = topic_prefix + "control" &redef;

    ## Record type to indicate a node in a cluster.
    type Node: record {
        ## The name of the cluster node
        name:         string;
        ## The IP address of the cluster node.
        ip:           addr;
        ## If the *ip* field is a non-global IPv6 address, this field
        ## can specify a particular :rfc:`4007` ``zone_id``.
        zone_id:      string      &default="";
        ## The port that this node will listen on for peer connections.
        p:            port;
        ## Identifier for the interface a worker is sniffing.
        interface:    string      &optional;
        ## A unique identifier assigned to the node by the broker framework.
        ## This field is only set while a node is connected.
        id: string                &optional;
    };

    const self: Node &redef;

    const peerings: vector of Node = vector() &redef;

    # XXX: can_accomodate function
}

# EVENT
global group_join_request: event(group: string, node_id: string, last_group_node: string);

global group_join_confirm: event(group: string);

global handover_request: event(group: string, node_ids: set[string]);

global handover_confirm: event(group: string, node_ids: set[string]);

global get_state: event();

global status: event(name: string, id: string, groups: set[string]);

# VARIABLES

# Groups that the node participates in
global groups: table[string] of bool;

# Children that the node acts a a parent for
# [group] -> [last_node] -> set(nodes)
global children: table[string] of table[string] of set[string];

function log(msg: string) {
    if (DEBUG) {
        print(msg);
        flush_all();
    }
}

function subscribe(topic: string) {
    log(fmt("[main.bro] => Subscribing to %s", topic));
    Broker::subscribe(topic);
}

function connect_initial_peers() {
    log(fmt("[main.bro]    Connecting to %d peer(s)", |peerings|));
    for (i in peerings) {
        local peer = peerings[i];
        local res = Broker::peer(cat(peer$ip), peer$p);
        log(fmt("[main.bro]    => Peering to %s:%d aka %s", cat(peer$ip), peer$p, peer$name));
    }
}

function node_topic(node_id: string): string {
    # XXX: Strip process id suffix?
    return node_topic_prefix + node_id;
}

function group(group: string): string {
    # XXX: sanitize group name?
    return group_topic_prefix + group;
}

function can_take_child(): bool {
    return T;
}

event bro_init() &priority=5 {
    # Set our own id in the Node
    self$id = Broker::node_id();

    log(fmt("[main.bro] Hi, I'm '%s' aka %s", self$name, self$id));

    # Listen on our node topic
    subscribe(node_topic(self$id));
    # and the global control topic
    subscribe(control_topic);
    Broker::forward(topic_prefix + "status");

    # Listen for incoming connections
    Broker::listen();

    connect_initial_peers();
    log("[main.bro] Finished bro_init()");
}


event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) {
    log(fmt("[main.bro] Broker::peer_added: %s [%s]", endpoint$id, msg));

    #print(fmt("[main.bro] Publishing group_join_confirm(%s) to %s", self$name, node_topic(endpoint$id)));
    #Broker::publish(node_topic(endpoint$id), DeepCluster::group_join_confirm, self$name);
}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string) {
    log(fmt("[main.bro] Broker::peer_removed: %s [%s]", endpoint$id, msg));
}

event DeepCluster::get_state() {
    log("[main.bro] DeepCluster::get_state");
    local tmp: set[string] = set();
    for (g in DeepCluster::groups) {
        add tmp[g];
    }
    Broker::publish(topic_prefix + "status", DeepCluster::status, self$name, self$id, tmp);
}

event DeepCluster::group_join_request(group: string, node_id: string, last_group_node: string) {
    if (group in groups) {
        if (groups[group]) {
            # We are parent for this group -> accept or reject new child
            if (can_take_child()) {
                # XXX: Add to children
                add children[group][last_group_node][node_id];
                Broker::publish(node_topic(node_id), DeepCluster::group_join_confirm, group);
            }
            else {
                # XXX: Initiate handover to last_hop
                local nodes = children[group][last_group_node];
                add nodes[node_id];
                Broker::publish(node_topic(last_group_node), DeepCluster::handover_request, group, nodes);
            }
        }
        else {
            # We are not parent of this group -> update last_hop
            # singlehop XXX: publish only in "other direction"
            event DeepCluster::group_join_request(group, node_id, self$id);
        }
    }
}


event DeepCluster::group_join_confirm(group: string) {
    # XXX: possibly verify this? What if we are already in the group?
    if (group in groups) {
        log(fmt("[main.bro] Got group_join_confirm for group I already joined: %s", group));
    }
    else {
        log(fmt("[main.bro] Got group_join_confirm: %s", group));
        groups[group] = F;
    }

}

event DeepCluster::handover_request(group: string, node_ids: set[string]) {
    log(fmt("[main.bro] DeepCluster::handover_request: %s (%d)", group, |node_ids|));

    local num_nodes = |node_ids|;
}

event DeepCluster::handover_confirm(group: string, node_ids: set[string]) {
    log(fmt("[main.bro] DeepCluster::handover_confirm: %s (%d)", group, |node_ids|));
}

