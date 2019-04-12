@load base/frameworks/broker

module DeepCluster;

export {

    const topic_prefix = "bro/deepcluster/" &redef;

    const node_topic_prefix = topic_prefix + "node/" &redef;

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
}

# EVENT
global group_join_request: event(group: string, node_id: string, last_group_node: string);

global group_join_confirm: event(group: string);

global handover_request: event(group: string, node_ids: vector of string);

global handover_confirm: event(group: string, node_ids: vector of string);

# VARIABLES
global groups: set[string];

function connect_peers() {
    print(fmt("[main.bro]    Connecting to %d peer(s)", |peerings|));
    for (i in peerings) {
        local peer = peerings[i];
        local res = Broker::peer(cat(peer$ip), peer$p);
        print(fmt("[main.bro]    => Peering to %s:%d=%s", cat(peer$ip), peer$p, cat(res)));
    }
}

event bro_init() &priority=5 {
    # Set our own id in the Node
    self$id = Broker::node_id();

    print(fmt("[main.bro] Hi, I'm %s aka %s", self$name, self$id));

    # Listen on our node topic
    print(fmt("[main.bro] => Subscribing to %s", node_topic_prefix + self$id));
    Broker::subscribe(node_topic_prefix + self$id);


    # Listen for incomming connections
    Broker::listen();

    connect_peers();
    print("[main.bro] Finished bro_init()");
    flush_all();
}


event Broker::peer_added(endpoint: Broker::EndpointInfo, msg: string) {
    print(fmt("[main.bro] Broker::peer_added: %s [%s]", endpoint$id, msg));

    print(fmt("[main.bro] Publishing group_join_confirm(%s) to %s", self$name, node_topic_prefix + endpoint$id));
    Broker::publish(node_topic_prefix + endpoint$id, DeepCluster::group_join_confirm, self$name);
    flush_all();
}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string) {
    print(fmt("[main.bro] Broker::peer_removed: %s [%s]", endpoint$id, msg));
    flush_all();
}

event DeepCluster::group_join_request(group: string, node_id: string, last_group_node: string) {
    if (group in groups) {
        # singlehop XXX: publish only in "other direction"
        event DeepCluster::group_join_request(group, node_id, self$id);
    }
}


event DeepCluster::group_join_confirm(group: string) {
    print(fmt("[main.bro] group_join_confirm(%s)", group));
    # XXX: possibly verify this?
    add groups[group];

    flush_all();
}

event DeepCluster::handover_request(group: string, node_ids: vector of string) {
}

event DeepCluster::handover_confirm(group: string, node_ids: vector of string) {
}

