@load base/frameworks/broker

module DeepCluster;

const DEBUG = T;

export {
    # SYSTEM CONFIG

    # Enable broker event forwarding
    redef Broker::forward_messages = T;

    # Check for unused event handler (that indicate a missspelled name for example)
    #redef check_for_unused_event_handlers = T;

    # TOPICS, PREFIXES AND SUFFIXES
    const topic_prefix = "bro/deepcluster/" &redef;

    const node_topic_prefix = topic_prefix + "node/" &redef;
    const group_topic_prefix = topic_prefix + "group/" &redef;
    const parent_topic_suffix = "/parent" &redef;

    const control_topic = topic_prefix + "control" &redef;

    # RECORDS

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
        id:           string      &optional;

        # Set of groups the node belongs to.
        # Defaults to empty set to simplify initialization
        groups:       set[string] &default=set();
        # Set of groups the node acts as a parent of.
        # Defaults to empty set to simplify initialization
        parent:       set[string] &default=set();
    };

    # VARIABLES
    const self: Node &redef;

    const peers: vector of Node = vector() &redef;

    # XXX: can_accomodate function

    # FUNCTIONS
    global can_take_child: function(): bool;

    global is_parent_of: function(node_id: string, group: string): bool;

    global create_group: function(group: string);
    global join_group: function(group: string);
    global leave_group: function(group: string);
}

# EVENTS
global _setup_initial_groups: event();

global group_join_request: event(group: string, node_id: string, sender: string, last_group_node: string);

global group_join_confirm: event(group: string);

global handover_request: event(group: string, node_ids: set[string]);

global handover_confirm: event(group: string, node_ids: set[string]);

global get_state: event();

global status: event(name: string, id: string, peer_ids: set[string], groups: set[string], children: set[string]);

# VARIABLES

global peer_ids: set[string] = set();

# Groups that the node participates in
global groups: table[string] of bool;

# Children that the node acts a a parent for
# [group] -> [last_node] -> set(nodes)
global children: table[string] of table[string] of set[string];

function _log(msg: string) {
    if (DEBUG) {
        print(msg);
        flush_all();
    }
}

function _subscribe(topic: string) {
    _log(fmt("[main.bro] => Subscribing to %s", topic));
    Broker::subscribe(topic);
}

function node_topic(node_id: string): string {
    # XXX: Strip process id suffix?
    return node_topic_prefix + node_id;
}

function group_topic(group: string): string {
    # XXX: sanitize group name?
    return group_topic_prefix + group;
}

function parent_topic(group: string): string {
    # XXX: sanitize group name?
    return group_topic(group) + parent_topic_suffix;
}

function can_take_child(): bool {
    return T;
}

function _get_peer_topics(sender: string): set[string] {
    local _peers = DeepCluster::peer_ids - set(sender);
    local _topics: set[string] = set();
    for (_p in _peers) {
        add _topics[node_topic(_p)];
    }

    return _topics;
}

function create_group(group: string) {
    _log(fmt("[main.bro] Creating group '%s'", group));
    _subscribe(group_topic(group));
    _subscribe(parent_topic(group));
    DeepCluster::groups[group] = T;
}

function join_group(group: string) {
    _log(fmt("[main.bro] Joining group '%s'", group));
    local _e = Broker::make_event(DeepCluster::group_join_request, group, self$id, self$id, self$id);
    for (_p in DeepCluster::peer_ids) {
        Broker::publish(node_topic(_p), _e);
    }
}

function _connect_initial_peers() {
    _log(fmt("[main.bro] Connecting to %d initial peer(s)", |peers|));
    for (i in peers) {
        local _peer = peers[i];
        local _res = Broker::peer(cat(_peer$ip), _peer$p);
        _log(fmt("[main.bro] => Peering to %s:%d aka %s", cat(_peer$ip), _peer$p, _peer$name));
    }
}

event _setup_initial_groups() {
    for (_g in DeepCluster::self$groups) {
        join_group(_g);
    }

    for (_g in DeepCluster::self$parent) {
        create_group(_g);
    }

}

event zeek_init() &priority=5 {
    _log("[main.bro] Begin zeek_init()");

    # Set our own id in the Node
    self$id = Broker::node_id();

    _log(fmt("[main.bro] Hi, I'm '%s' aka %s", self$name, self$id));

    # Listen on our node topic
    _subscribe(node_topic(self$id));
    # and the global control topic
    _subscribe(control_topic);

    # Also forward the global status topic XXX: Maybe revisit this
    Broker::forward(topic_prefix + "status");

    # Listen for incoming connections
    Broker::listen();

    # Setup initial state
    _connect_initial_peers();
    schedule 5sec { DeepCluster::_setup_initial_groups() };

    _log("[main.bro] Finished zeek_init()");
}

event Broker::peer_added(endpoint: Broker::EndpointInfo, _: string) {
    local _remote_id = endpoint$id;
    local _remote_ip = endpoint$network$address;
    _log(fmt("[main.bro] Broker::peer_added: %s@%s", _remote_id, _remote_ip));

    add peer_ids[_remote_id];
}

event Broker::peer_removed(endpoint: Broker::EndpointInfo, _: string) {
    local _remote_id = endpoint$id;
    local _remote_ip = endpoint$network$address;
    _log(fmt("[main.bro] Broker::peer_removed: %s@%s", _remote_id, _remote_ip));

    delete peer_ids[_remote_id];
}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, _: string) {
    local _remote_id = endpoint$id;
    local _remote_ip = endpoint$network$address;
    _log(fmt("[main.bro] Broker::peer_lost: %s@%s", _remote_id, _remote_ip));

    delete peer_ids[_remote_id];
}

event DeepCluster::get_state() {
    _log("[main.bro] DeepCluster::get_state");
    local _groups: set[string] = set();
    for (_g in DeepCluster::groups) {
        add _groups[_g];
    }
    local _children: set[string] = set();
    for (_c in DeepCluster::children) {
        add _children[_c];
    }

    local e = Broker::make_event(DeepCluster::status, self$name, self$id, peer_ids, _groups, _children);
    Broker::publish(topic_prefix + "status", e);
}

event DeepCluster::group_join_request(group: string, node_id: string, sender: string, last_group_node: string) {
    #_log(fmt("[main.bro] DeepCluster::group_join_request for group '%s', node_id=%s, sender=%s, last_group_node=%s", group, node_id, sender, last_group_node));
    local _topics: set[string] = set();

    if (group in groups) {
        # We are part of the group
        if (groups[group]) {
            # We are parent for this group -> accept or reject new child

            if (can_take_child()) {
                # We can take in the child -> publish `group_join_confirm`
                _log(fmt("[main.bro] Accepting child for group '%s' (id=%s)", group, node_id));

                if (group !in children) {
                    children[group] = table();
                }
                if (last_group_node !in children[group]) {
                    children[group][last_group_node] = set();
                }
                add children[group][last_group_node][node_id];
                local gjc = Broker::make_event(DeepCluster::group_join_confirm, group);
                Broker::publish(node_topic(node_id), gjc);
            }
            else {
                # We cannot take in the child -> initiate `handover_request`
                _log(fmt("[main.bro] Initiating handover for group '%s' to %s", group, last_group_node));

                local _nodes: set[string] = set();
                if (group in children && last_group_node in children[group]) {
                    _nodes = children[group][last_group_node];
                }
                add _nodes[node_id];
                local hr = Broker::make_event(DeepCluster::handover_request, group, _nodes);
                Broker::publish(node_topic(last_group_node), hr);
            }
        }
        else {
            # We are not parent of this group -> update `last_group_node`
            local gjr = Broker::make_event(DeepCluster::group_join_request, group, node_id, self$id, self$id);
            _topics = _get_peer_topics(sender);
            for (_t in _topics) {
                _log(fmt("[main.bro] Publishing updated group_join_request by %s for group '%s' to %s", node_id, group, _t));
                Broker::publish(_t, gjr);
            }
        }
    }
    else {
        # We are not part of the group -> just pass the event further up
        local fwd = Broker::make_event(DeepCluster::group_join_request, group, node_id, self$id, last_group_node);
        _topics = _get_peer_topics(sender);
        for (_t in _topics) {
            _log(fmt("[main.bro] Forwarding group_join_request by %s for group '%s' to %s", node_id, group, _t));
            Broker::publish(_t, fwd);
        }
    }
}

event DeepCluster::group_join_confirm(group: string) {
    # XXX: possibly verify this?
    if (group !in groups) {
        _log(fmt("[main.bro] Confirming group membership for group '%s'", group));
        groups[group] = F;
    }
    else {
        _log(fmt("[main.bro] Got unexpected group_join_confirm for group '%s' which I already joined", group));
    }

}

event DeepCluster::handover_request(group: string, node_ids: set[string]) {
    _log(fmt("[main.bro] DeepCluster::handover_request: %s (%d)", group, |node_ids|));

    local num_nodes = |node_ids|;
}

event DeepCluster::handover_confirm(group: string, node_ids: set[string]) {
    _log(fmt("[main.bro] DeepCluster::handover_confirm: %s (%d)", group, |node_ids|));
}

